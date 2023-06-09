import logging
import os
import platform
import subprocess

def is_windows():
    return platform.system() == 'Windows'

def run_tool(exes, *args, **kwargs):
    if isinstance(exes, list):
        for exe in exes:
            try:
                return run_tool(exe, *args, **kwargs)
            except FileNotFoundError as e:
                logging.debug(f'Error running {exe}: {e}')
        raise(FileNotFoundError('No executables were found'))
    elif isinstance(exes, str):
        cwd = kwargs['cwd'] if 'cwd' in kwargs else os.getcwd()
        return_output = kwargs.get('return_output', False)
        logging.debug(f"Launching command: {exes} with args [{args}]")
        r = subprocess.run(args=[exes] + list(args), cwd=cwd, capture_output=return_output)
        if return_output:
            return r.stdout.decode('utf-8')
        else:
            return r
    else:
        raise(TypeError("Input 'exes' to run_tool must be a list or a string"))
