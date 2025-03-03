import os
import random
import string

def generate_secret_key(length=50):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def update_env_file(secret_key):
    env_file_path = '/d:/OSINT/.env'
    with open(env_file_path, 'r') as file:
        lines = file.readlines()
    
    with open(env_file_path, 'w') as file:
        for line in lines:
            if line.startswith('SECRET_KEY='):
                file.write(f'SECRET_KEY={secret_key}\n')
            else:
                file.write(line)

if __name__ == "__main__":
    new_secret_key = generate_secret_key()
    update_env_file(new_secret_key)
    print("Secret key updated successfully.")
