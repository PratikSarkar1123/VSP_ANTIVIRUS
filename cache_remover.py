import os

# Temporary file remover
def CacheFileRemover():
    temp_list = list()
    username = os.environ.get('USERNAME').upper().split(" ")

    for (dirpath, dirnames, filenames) in os.walk("C:\\Windows\\Temp"):
        temp_list += [os.path.join(dirpath, file) for file in filenames]
        temp_list += [os.path.join(dirpath, file) for file in dirnames]

    
    if temp_list:
        for i in temp_list:
            print(f"Removing: {i}")
            try:
                os.remove(i)
            except Exception as e:
                print(f"Error removing file {i}: {e}")

            try:
                os.rmdir(i)
            except Exception as e:
                print(f"Error removing directory {i}: {e}")
    else:
        return 0
