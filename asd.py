import subprocess

if __name__ == "__main__":
    command = "bash"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE,
                               shell=True)

    # Пример отправки команды
    command_to_send = "ls -l"
    process.stdin.write(command_to_send.encode('utf-8'))
    process.stdin.write(b'\n')  # Добавляем новую строку, если нужно

    # Получить вывод
    output, errors = process.communicate()

    # Декодируем вывод в строку
    output_str = output.decode('utf-8')

    print(output_str)
