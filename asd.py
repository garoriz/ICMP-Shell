import subprocess

if __name__ == "__main__":
    command = "ls -l"
    result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, text=True)

    # Получить вывод команды
    output = result.stdout
    print(output)
