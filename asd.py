def split_string_by_bytes(input_string, byte_length):
    utf8_bytes = input_string
    byte_chunks = [utf8_bytes[i:i+byte_length] for i in range(0, len(utf8_bytes), byte_length)]
    return byte_chunks


if __name__ == '__main__':
    s = "\"ыва\" не"
    byte_length = 5
    result = split_string_by_bytes(s, 200)

    my_bytes = len(s.encode('utf-8'))
    print(result)
