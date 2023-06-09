import os

# Join paths using standard os.path.join, but ensure that the returned path is fully normalised
# and that the Unix-like path separator is always used.
def join(path, *paths):
    return os.path.normpath(os.path.join(path, *paths)).replace('\\','/')

def realpath(path):
    return os.path.realpath(path).replace('\\','/')