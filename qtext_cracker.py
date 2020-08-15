import sys
import os
import itertools
import argparse
import tqdm
import json
from collections import defaultdict

BANNER = """
       _____         _        ____                _             
   __ |_   _|____  _| |_     / ___|_ __ __ _  ___| | _____ _ __ 
  / _` || |/ _ \ \/ / __|   | |   | '__/ _` |/ __| |/ / _ \ '__|
 | (_| || |  __/>  <| |_    | |___| | | (_| | (__|   <  __/ |   
  \__, ||_|\___/_/\_\\__|    \____|_|  \__,_|\___|_|\_\___|_|   
     |_|                                                        

"""

def print_banner():
    print(BANNER)
    
# Taken from binary
BITMAP = b"\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80"
def is_valid_char(c):
    # Can be simplified as 0x21 < c < 0x100
    assert type(c) is int
    assert c <= 0xff
    upper_idx = c >> 3 # upper 5 bits
    lower_idx = c & 0b111 # Lower 3 bits
    return not bool((BITMAP[upper_idx] >> lower_idx) & 1)

def key_transform(input_key, modifier=0x22):
    assert type(input_key) is bytearray
    key = bytearray(input_key) # copy
    for i in range(len(key)):
        for j in range(len(key)):
            key[i] = (key[i] + key[j]) & 0xFF
        while not is_valid_char(key[i]):
            key[i] = (key[i] + modifier) & 0xFF
    return key


def recursive_decomposition(input_key, decomposed_part=None, stop_at=4):
    assert type(input_key) is bytearray
    key = bytearray(input_key) # copy
    if decomposed_part is None:
        decomposed_part = bytearray()

    if len(key) == 0:
        # Stopping condition 
        return [decomposed_part,]

    if stop_at is not None:
        if len(decomposed_part) >= stop_at:
            return [decomposed_part,]

    results = []
    value = key.pop()
    if not is_valid_char((value - 0x22) % 0x100):
        # We have an additional case to process 
        new_key = bytearray(key) # copy
        new_key.append((value - 0x22) % 0x100)
        # Where to save this?
        results.extend(recursive_decomposition(new_key, decomposed_part, stop_at))
    
    value = (value - sum(decomposed_part)) % 0x100
    # Subtract trailing (decomposed) characters
    # Compute two candidates
    candidate_1 = ((value // 2) - sum(key)) % 0x100
    candidate_2 = (((0x100 + value) // 2) - sum(key)) % 0x100
    new_decomposed_left = bytearray([candidate_1,]) + decomposed_part
    new_decomposed_right = bytearray([candidate_2,]) + decomposed_part

    results.extend(recursive_decomposition(key, new_decomposed_left, stop_at))
    results.extend(recursive_decomposition(key, new_decomposed_right, stop_at))

    return results
    
def expand_key(key):
    return key_transform(key_transform(bytearray(key))*4).hex()

# Passcode valid bytes
#VALID_BYTES = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+}{[]\"';:/?.>,<`~|\\"  # seems like it should be all these, but it turns out be:
VALID_BYTES = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890,." 
def brute_force_dictionary():
    # Should be all of them
    key_space_size = len(VALID_BYTES) ** 4
    output_dict = {}
    print("Computing all possible passcodes.")
    with tqdm.tqdm(total=key_space_size) as progress_bar:
        for combination in itertools.product(VALID_BYTES, repeat=4):
            passcode = bytearray(combination)
            output_dict[expand_key(passcode)] = passcode.decode("latin1")
            progress_bar.update(1)

    return output_dict

def get_key_from_document(document_path):
    # Read key from file, format of first line is:
    #   FF 20 FF 20 FF 20 FF 20 FF 20 30 30 20 6C 89 97 75 77 AA FA
    #   9E F2 3D 91 63 41 2A 58 B8 0D 0A
    try:
        key = open(document_path ,"rb").read(0x1d).lstrip(bytes.fromhex('ff20ff20ff20ff20ff20303020'))
    except IOError as e:
        print("Could not open target document", file=sys.stderr)
        return None
    return key

def brute_force(document, cached_dict):
    # Get key
    key = get_key_from_document(document).hex()
    if not key:
        return -1

    key_dict = None
    if os.path.exists(cached_dict):
        try:
            key_dict = json.load(open(cached_dict))
        except (IOError, json.JSONDecodeError) as e:
            print("Could not open key dict, attempting to regenerate.", file=sys.stderr)
            key_dict = None

    if key_dict == None:
        key_dict = brute_force_dictionary()
        try:
            json.dump(key_dict, open(cached_dict, "w"), indent=4)
        except IOError as e:
            print("Could not write key dict to cache file.", file=sys.stderr)

    print("File key is: %r" % key)
    print("Passcode is: %r" % key_dict[key])

    return 0

def decompose_key(document):
    # Get key
    key = bytearray(get_key_from_document(document))
    if not key:
        return -1

    # Decompose partially to recover 4 last bytes of the key
    initial_decomposition_results = recursive_decomposition(key)
    if len(initial_decomposition_results) == 0:
        print("Could not decompose key!", file=sys.stderr)
        return -1

    # Find the correct 4 bytes by re-transforming each option and comparing to the original key
    filtered_results = [_ for _ in initial_decomposition_results if key_transform(_*4) == key]
    if len(filtered_results) == 0:
        print("Could not find matching result.", file=sys.stderr)
        return -1
    elif len(filtered_results) != 1:
        print("Warning - multiple decomposition results, proceeding with first match.")

    matched_key = filtered_results.pop()

    # Once that is found, decompose once again and find the printable option
    second_decomposition_results = recursive_decomposition(matched_key)
    if len(initial_decomposition_results) == 0:
        print("Could not decompose mid point key!", file=sys.stderr)
        return -1

    def is_fully_printable(passcode):
        return all(_ in VALID_BYTES for _ in passcode)
    second_filtered_results = [_ for _ in second_decomposition_results if is_fully_printable(_)]
    if len(second_filtered_results) == 0:
        print("Could not find matching mid point result.", file=sys.stderr)
        return -1
    elif len(second_filtered_results) != 1:
        print("Warning - multiple mid point decomposition results, proceeding with first match.")
        print(second_filtered_results)

    print("File key is: %r" % key.hex())
    print("Passcode is: %r" % second_filtered_results.pop().decode("latin1"))

    return 0
    
    

def main():
    print_banner()
    parser = argparse.ArgumentParser("Tool for cracking qtext passwords.")
    subparser = parser.add_subparsers(help="Type of attack to conduct", dest="command")
    parser.add_argument("document", type=str, help="QTEXT document to crack")

    decompose_parser = subparser.add_parser("decompose")
    brute_force_parser = subparser.add_parser("brute-force")
    brute_force_parser.add_argument(
        "-c", "--cached-dict", type=str, default="qtext.json", help="Cached brute force dictionary, if doesnt exist will be generated."
    )

    args = parser.parse_args()
    if args.command == "brute-force":
        return brute_force(args.document, args.cached_dict)
    elif args.command == "decompose":
        return decompose_key(args.document)
    else:
        raise NotImplementedError

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Aborting...", file=sys.stderr)
        sys.exit(-1)
