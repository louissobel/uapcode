import sys
import os

def fix_up_pythonpath():
    """
    gets the 'code' folder in the path.
    This makes so we can find flask_attestation and requests_attestation
    """
    this_files_dir = os.path.dirname(os.path.abspath(__file__))
    dir_up_one = os.path.join(this_files_dir, '..')
    sys.path.insert(0, dir_up_one)
