from typing import Optional


def print_data(buffer_name: Optional[str], buffer: Optional[str], buffer_length: int, column_length: int) -> None:
    if buffer is None:
        print("Buffer is NULL.")
        return

    if buffer_length <= 0:
        print("Buffer length must be greater than zero.")
        return

    if column_length <= 0:
        print("Column length must be greater than zero.")
        return

    buffer = bytes.fromhex(buffer)
    buffer_length = len(buffer)
    
    if buffer_name is None:
        print(f"No Name[{buffer_length}]")
    else:
        print(f"{buffer_name}[{buffer_length}]")

    full_rows = buffer_length // column_length
    
    for i in range(full_rows):
        start = i * column_length
        hex_bytes = buffer[start:start+column_length]
        hex_str = ' '.join(f"{b:02x}" for b in hex_bytes)
        print(f"[0x{start:08x}]: {hex_str}")

    remaining = buffer_length % column_length
    if remaining != 0:
        start = full_rows * column_length
        hex_bytes = buffer[start:start+remaining]
        hex_str = ' '.join(f"{b:02x}" for b in hex_bytes)
        print(f"[0x{start:08x}]: {hex_str}")
