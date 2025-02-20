import numpy as np
import time

class Playfair:
    alphabet = ['a','b','c','d','e','f','g','h','i','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z']

    def __init__(self, secret_key, display=True):  # Added display parameter
        self.playfair_dict_1 = {}
        self.playfair_dict_2 = {}
        self.secret = secret_key.lower().replace(" ", "")
        self.playfair_table()
        if display:  # Only display table when needed
            self.display_table()

    def display_table(self):
        playfair_table = np.reshape(list(self.playfair_dict_2.keys()), (5, 5))
        print("Playfair Table:")
        print(playfair_table)

    ## get only unique chars
    def unique(self, secret): ## from - https://stackoverflow.com/questions/9792664/converting-a-list-to-a-set-changes-element-order
        seen = set()
        return [x for x in secret if not (x in seen or seen.add(x))]

    ## change j to i
    def j_to_i(self, sequence):
        return ''.join(['i' if x == 'j' else x for x in sequence])

    # Handle repeating letters by inserting 'x' between them
    def repeat_letters(self, plaintext):
        i = 0
        while i < len(plaintext) - 1:
            if (plaintext[i] == plaintext[i+1]) and (i%2==0):
                plaintext = plaintext[:i+1] + 'x' + plaintext[i+1:]
            i += 1
        return plaintext

    def pad(self, plaintext):
        if (len(plaintext) % 2) == 1:
            plaintext = plaintext+'x'
        return plaintext

    def digrams(self, text):
        return [text[i:i+2] for i in range(0, len(text), 2)]

    def preprocess(self, plaintext):
        p = plaintext.lower().replace(" ", "")
        p = self.repeat_letters(p)
        p = self.j_to_i(p)
        p = self.pad(p)
        return self.digrams(p)

    ## full steps to buld table (2 dicts for implementation purposes)
    def playfair_table(self):
        print("secret :", self.secret)
        secret = self.unique(self.j_to_i(self.secret))
        playfair_alp_set = secret + [x for x in self.alphabet if x not in secret]
        for i in range(1, 26):
            self.playfair_dict_1[i] = playfair_alp_set[i-1]
            self.playfair_dict_2[playfair_alp_set[i-1]] = i

    def playfair_encrypt(self,digram):

        letters = [x for x in digram]

        index_arr = [5,1,2,3,4,5,1]

        ## decoding the rows and cols from dict
        row1 = ((self.playfair_dict_2[letters[0]]-1) // 5) + 1 
        row2 = ((self.playfair_dict_2[letters[1]]-1) // 5) + 1
        col1 = ((self.playfair_dict_2[letters[0]]-1) % 5) + 1
        col2 = ((self.playfair_dict_2[letters[1]]-1) % 5) + 1

        ## encrypt to nums
        if row1==row2:
            col1 = index_arr[col1 + 1]
            col2 = index_arr[col2 + 1]

        elif col1==col2:
            row1 = index_arr[row1 + 1]
            row2 = index_arr[row2 +1]

        else:
            col1, col2 = col2, col1

        return self.playfair_dict_1[(row1-1)*5 + col1] + self.playfair_dict_1[(row2-1)*5 + col2]

    def playfair_decrypt(self, enc_digram):
        letters = list(enc_digram)
        index_arr = [5,1,2,3,4,5,1]

        ## decoding the rows and cols from dict
        row1 = ((self.playfair_dict_2[letters[0]]-1) // 5) + 1 
        row2 = ((self.playfair_dict_2[letters[1]]-1) // 5) + 1

        col1 = ((self.playfair_dict_2[letters[0]]-1) % 5) + 1## check here
        col2 = ((self.playfair_dict_2[letters[1]]-1) % 5) + 1

        ## encrypt to nums
        if row1==row2:
            col1 = index_arr[col1 - 1]
            col2 = index_arr[col2 - 1]

        elif col1==col2:
            row1 = index_arr[row1 - 1]
            row2 = index_arr[row2 - 1]

        else:
            col1, col2 = col2, col1 ## swap cols

        return self.playfair_dict_1[(row1-1)*5 + col1] + self.playfair_dict_1[(row2-1)*5 + col2]

    def encrypt(self, plaintext):
        digrams = self.preprocess(plaintext)
        return ''.join(self.playfair_encrypt(digram) for digram in digrams)

    def decrypt(self, encrypted):
        digrams = self.digrams(encrypted)
        return ''.join(self.playfair_decrypt(digram) for digram in digrams)


def rail_fence_encrypt(plaintext, depth):
    # Initialize an empty rail fence matrix with spaces
    rail = [[' ' for _ in range(len(plaintext))] for _ in range(depth)]
    
    row, step = 0, 1  # Start at the first row, moving downward
    for i, char in enumerate(plaintext):
        rail[row][i] = char  # Place character in the matrix
        row += step  

        if row == 0 or row == depth - 1: # Change direction when reaching the top or bottom row
            step *= -1  

    # display the Rail Fence matrix for visualization
    print("\nRail Fence Matrix:")
    for r in rail:
        print("".join(r))

    # Read encrypted text row-wise (concatenating characters from each row)
    return ''.join(rail[r][c] for r in range(depth) for c in range(len(plaintext)) if rail[r][c] != ' ')


def rail_fence_decrypt(ciphertext, depth):
   # determine how many characters each row gets
    rail_lengths = [0] * depth  # Track how many characters per row
    row, step = 0, 1

    for _ in ciphertext:
        rail_lengths[row] += 1  
        row += step  
        if row == 0 or row == depth - 1:
            step *= -1  

    # fill the rail matrix row-wise with ciphertext characters
    rails, index = [[] for _ in range(depth)], 0
    for i in range(depth):
        rails[i] = list(ciphertext[index:index + rail_lengths[i]])  # Slice characters into the correct row
        index += rail_lengths[i]  

    # read the matrix in a zig-zag order to reconstruct the original text
    row, step, plaintext = 0, 1, []
    rail_pointers = [0] * depth  # Track the position in each row

    for _ in ciphertext:
        plaintext.append(rails[row][rail_pointers[row]])  # Read the next character
        rail_pointers[row] += 1  
        row += step  
        if row == 0 or row == depth - 1:
            step *= -1 

    return ''.join(plaintext)  



def encrypt_combined(plaintext, key, depth): #combining both cipher
    playfair = Playfair(key)
    playfair_encrypted = playfair.encrypt(plaintext)
    return rail_fence_encrypt(playfair_encrypted, depth)


def decrypt_combined(ciphertext, key, depth):
    playfair = Playfair(key, display=False)  # Prevent duplicate table display
    rail_decrypted = rail_fence_decrypt(ciphertext, depth)
    return playfair.decrypt(rail_decrypted)



if __name__ == "__main__":
    plaintext = input("Insert the plaintext:")
    key = input("Insert the secret key: ")
    depth = int(input("Enter the Rail Fence depth (2-5): "))

    encrypted = encrypt_combined(plaintext, key, depth)
    print(f"Encrypted: {encrypted}")

    decrypted = decrypt_combined(encrypted, key, depth)
    print(f"Decrypted: {decrypted}")
