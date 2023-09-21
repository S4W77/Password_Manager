def windows():
    try:
        import sys
        def the_block():
            import importlib

            def encrypt():
                while True:

                    import os
                    import json
                    import sys
                    import subprocess
                    from Crypto.Cipher import AES
                    from Crypto.Random import get_random_bytes
                    from Crypto.Protocol.KDF import PBKDF2
                    import base64
                    from prompt_toolkit import prompt
                    from prompt_toolkit.completion import PathCompleter
                    import pyfiglet

                    font = pyfiglet.Figlet()
                    CRD = font.renderText(f"\n        {os.path.basename(__file__)}")

                    completer = PathCompleter()
                
                    def clear():
                        os.system("cls")

                    def options():

                        options_list = [
                            "\nOptions:",
                            "\n\t[00] - Exit",
                            "\t[01] - Clear the screen",
                            "\t[02] - Encrypt a password",
                            "\t[03] - Decrypt passwords from a file",
                            "\t[04] - Read file",
                            "\t[05] - Clear file",
                            "\t[06] - Delete file",
                            "\t[07] - List files",
                            "\t[08] - Reload script\n",
                            "\t[99] - Credits\n",
                            ''
                        ]

                        index = len(options_list)

                        for i in range(index):
                            print(options_list[i])

                    def encrypt_password(password, encryption_key):
                        cipher = AES.new(encryption_key, AES.MODE_GCM)
                        ciphertext, tag = cipher.encrypt_and_digest(password.encode())
                        return cipher.nonce + ciphertext + tag

                    def decrypt_password(encrypted_password, encryption_key):
                        nonce = base64.b64decode(encrypted_password['nonce'])
                        ciphertext = base64.b64decode(encrypted_password['ciphertext'])
                        tag = base64.b64decode(encrypted_password['tag'])
                        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                        return plaintext.decode()

                    def derive_key_from_password(password, salt):
                        key = PBKDF2(password, salt, dkLen=32, count=1000000)
                        return key

                    def save_encrypted_password(encrypted_password, encryption_key, salt, file_path):
                        entry = {
                            'salt': base64.b64encode(salt).decode(),
                            'nonce': base64.b64encode(encrypted_password[:16]).decode(),
                            'ciphertext': base64.b64encode(encrypted_password[16:-16]).decode(),
                            'tag': base64.b64encode(encrypted_password[-16:]).decode(),
                            'encryption_key': base64.b64encode(encryption_key).decode(),
                        }

                        with open(file_path, 'a') as file:
                            file.write(json.dumps(entry) + '\n')

                    def load_encrypted_passwords(file_path):
                        encrypted_passwords = []
                        with open(file_path, 'r') as file:
                            for line in file:
                                entry = json.loads(line)
                                encrypted_passwords.append(entry)
                        return encrypted_passwords

                    try:
                        options()

                        choice = input("Enter your option: ").strip().lower().replace(" ", "")

                        if choice in ['0', '00', '000', '0000', '00000', '000000']:
                            print("\nQuitting...")
                            print('')
                            os._exit(1)
                        elif choice in ['1', '01', '001', '0001', '00001', '000001']:
                            clear()
                        elif choice in ['2', '02', '002', '0002', '00002', '000002']:
                            password = input("\nEnter the password to encrypt: ")
                            salt = get_random_bytes(16)
                            encryption_key = derive_key_from_password(password.encode(), salt)
                            encrypted_password = encrypt_password(password, encryption_key)
                            while True:
                                file_path = prompt("Enter the file path to save the encrypted password: " , completer=completer, complete_while_typing=True)

                                try:
                                    save_encrypted_password(encrypted_password, encryption_key, salt, file_path)
                                    print("Encrypted Password:", base64.b64encode(encrypted_password).decode() + "\n")
                                    break
                                except FileNotFoundError:
                                    print(f"File '{os.path.basename(file_path)}' not found. Please provide a valid file path.\n")
                                except PermissionError:
                                    print(f"\nPermission denied for saving ecnrypted password in '{os.path.basename(file_path)}'\n")

                        elif choice in ['3', '03', '003', '0003', '00003', '000003']:
                            file_path = prompt("\nEnter the file path with the encrypted passwords: " , completer=completer, complete_while_typing=True)
                            try:
                                encrypted_passwords = load_encrypted_passwords(file_path)
                                print("\nDecrypted Passwords:\n")
                                counter = 1
                                for entry in encrypted_passwords:
                                    encryption_key = base64.b64decode(entry['encryption_key'])
                                    decrypted_password = decrypt_password(entry, encryption_key)
                                    print(f"{counter} - Key: {decrypted_password}")
                                    counter += 1
                                print('')
                            except FileNotFoundError:
                                print(f"File '{os.path.basename(file_path)}' not found.\n")
                            except PermissionError:
                                print(f"\nPermission denied for decrypting passwords in '{os.path.basename(file_path)}'\n")

                        elif choice in ['4', '04', '004', '0004', '00004', '000004']:
                            file_path = prompt("\nEnter the file path to read: " , completer=completer, complete_while_typing=True)
                            try:
                                if file_path.endswith('.txt'):
                                    with open(file_path) as f:
                                        file_content = f.read()
                                        if file_content:
                                            print("\nFile Content:\n")
                                            print(file_content + '\n')
                                        else:
                                            print("\nFile is empty, Nothing to read\n")
                                        f.close()
                                else:
                                    print("\nUnssuported format, We only support .txt format\n")
                            except FileNotFoundError:
                                print(f"\nNo file as '{os.path.basename(file_path)}' was found\n")
                            except PermissionError:
                                print(f"\nPermission denied for reading '{os.path.basename(file_path)}'\n")
                        elif choice in ['5', '05', '005', '0005', '00005', '000005']:
                            file_path = prompt("\nEnter the file path to clear: " , completer=completer, complete_while_typing=True)
                            try:
                                if file_path.endswith('.txt'):
                                    with open(file_path) as file:
                                        f = file.read()
                                        if f:
                                            open(file_path, 'w').close()
                                            print(f"\nSuccessfully cleared '{os.path.basename(file_path)}'\n")
                                        else:
                                            print("\nFile is empty, Nothing to clear\n")
                                        file.close()
                                else:
                                    print("\nUnssuported format, We only support .txt format\n")
                            except FileNotFoundError:
                                print(f"\nNo file as '{os.path.basename(file_path)}' was found\n")
                            except PermissionError:
                                print(f"\nPermission denied for clearing '{os.path.basename(file_path)}'\n")
                        elif choice in ['6', '06', '006', '0006', '00006', '000006']:
                            file_path = prompt("\nEnter the file path to delete: " , completer=completer, complete_while_typing=True)
                            try:
                                if file_path.endswith('.txt'):
                                    os.remove(file_path)
                                    print(f"\nSuccessfully deleted '{os.path.basename(file_path)}'\n")
                                else:
                                    print("\nUnssuported format, We only support .txt format\n")
                            except FileNotFoundError:
                                print(f"\nNo file such as '{os.path.basename(file_path)}' was found\n")
                            except PermissionError:
                                print(f"\nPermission denied for deleting '{os.path.basename(file_path)}'\n")

                        elif choice in ['7', '07', '007', '0007', '00007', '000007']:

                            directory = input("\nEnter the directory path (skip for current directory): ").strip().replace(' ', '')

                            def ls(directory="."):
                                try:
                                    with os.scandir(directory) as entries:
                                        files_and_folders = [entry.name for entry in entries]
                                        formatted_files_and_folders = " - ".join(files_and_folders)
                                        print(formatted_files_and_folders)
                                except FileNotFoundError:
                                    print(f"\nDirectory '{directory}' not found\n")
                                except PermissionError:
                                    print(f"\nPermission denied for directory '{directory}'\n")

                            if not directory:
                                directory = "."
                            print("")
                            ls(directory)
                            print("")
                        elif choice in ['8', '08', '008', '0008', '00008', '000008']:
                            is_running = True
                            print("\nReloading script...\n")
                            time.sleep(0.5)
                            os.system("cls")
                            subprocess.run(["python", __file__])
                            is_running = False
                            return

                        elif choice == "99":
                            clear()
                            print(CRD)
                            print("\n\tDeveloper: SpiringCord\n")
                            print("\tI was bored so i made this script. Don't do the same thing, it may take a while\n")
                            input("\n\tPress [Enter] to continue")
                            clear()

                        else:
                            print("Invalid choice. Please select a valid option.\n")

                    except Exception as e:
                        print(f"\nAn error has occurred: {e}\n")

            try:
                if __name__ == "__main__":
                    encrypt()

            except Exception as e:
                print(f"\nAn error has occured while loading the script : {e}\n")

        if sys.version_info < (3, 8):
            print("\nError: This script requires Python 3.8.x or higher to run.\n")
            sys.exit(1)
        
        def check_dependencies(required_packages):
            missing_packages = []
            probable_packages = {
                "Crypto": "pycryptodome",
                "base64": "pybase64",
                "prompt_toolkit": "prompt_toolkit",
                "pyfiglet": "pyfiglet"
            }
            
            for package in required_packages:
                try:
                    import importlib
                    importlib.import_module(package)
                except ImportError:
                    probable_package = probable_packages.get(package, '"Unknown"')
                    missing_packages.append((package, probable_package))

            return missing_packages

        required_packages = ["json", "prompt_toolkit", "sys", "base64", "os", "Crypto", "subprocess", "msvcrt", "pyfiglet"]

        missing_packages = check_dependencies(required_packages)

        if missing_packages:
            count = 0
            print("\nMissing packages:\n")
            for package, probable_package in missing_packages:
                count += 1
                print(f'{count}- Package: "{package}" | Probable package name: "{probable_package}"')
            def ask_installation(probable_package):
                pip = input("\nWould you like to install the missing packages [1-y/2-n]: ").lower().strip()
                if pip in ['1', 'y', 'yes', 'ye', 'yeah', 'yup', 'yea', 'yeh']:
                    def install():
                        try:
                            def install():
                                try:
                                    import subprocess
                                    subprocess.run(['pip', 'install'] + [p[1] for p in missing_packages], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                                    print("\nSuccessfully installed the missing packages!\n")
                                except subprocess.CalledProcessError as e:
                                    print(f"An error has occurred during installation: {e.stderr}\n")
                                import time
                                time.sleep(0.5)
                                import os
                                os.system('cls')
                                the_block()

                            install()
                        except Exception as e:
                            print(f"An error has occured: {e}")
                    install()
                elif pip in ['2', 'n', 'no', 'nah', 'nope', 'na']:
                    import os
                    os._exit(1)
                else:
                    return ask_installation(probable_package)

            for package, probable_package in missing_packages:
                ask_installation(probable_package)
        else:
            import os
            import time
            def clear():
                os.system("cls")
            def sleep():
                time.sleep(0.5)
            clear()
            sleep()
            print('')
            print("\nAll required packages are installed. Script can proceed\n")
            sleep()
            the_block()

    except KeyboardInterrupt:
        def handle_keyboard_interrupt():
            try:
                response = input("\nInterruption detected, Would you like to exit [1-y/2-n]: ").strip().lower().replace(" ", "")
                if response in ['1', 'y', 'yes', 'ye', 'yeah', 'yup', 'yea', 'yeh']:
                    print("\nQuitting...")
                    print('')
                    os._exit(1)
                elif response in ['2', 'n', 'no', 'nah', 'nope', 'na']:
                    print('')
                    the_block()
                else:
                    print(f'\nUnsupported response: "{response}"')
                    return handle_keyboard_interrupt()
            except KeyboardInterrupt:
                return handle_keyboard_interrupt()

        handle_keyboard_interrupt()

if __name__ == "__main__":
    import platform
    current_os = platform.system()
    if current_os == "Windows":
        windows()
    else:
        print("The current operating system is not Windows. Please reconsider using Windows to execute this script.")
