
## ------------------Playfair---------------- ##
class Playfair:
    alphabet = ['a','b','c','d','e','f','g','h','i','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z']

    def __init__(self, secret_key):
        self.playfair_dict_1 = {}
        self.playfair_dict_2 = {}
        self.secret = secret_key.lower().replace(" ", "")
        self.playfair_table()

    def unique(self, secret):
        seen = set()
        return [x for x in secret if not (x in seen or seen.add(x))]

    def j_to_i(self, sequence):
        return sequence.replace('j', 'i')

    def repeat_letters(self, plaintext):
        i = 0
        while i < len(plaintext) - 1:
            if plaintext[i] == plaintext[i+1] and i % 2 == 0:
                plaintext = plaintext[:i+1] + 'x' + plaintext[i+1:]
            i += 1
        return plaintext

    def pad(self, plaintext):
        return plaintext + 'x' if len(plaintext) % 2 == 1 else plaintext

    def digrams(self, text):
        return [text[i:i+2] for i in range(0, len(text), 2)]

    def preprocess(self, plaintext):
        p = plaintext.lower().replace(" ", "")
        p = self.j_to_i(p)
        p = self.repeat_letters(p)
        p = self.pad(p)
        return self.digrams(p)

    def playfair_table(self):
        secret = self.j_to_i(self.secret)
        secret_key = self.unique(secret)
        playfair_alp_set = secret_key + [x for x in self.alphabet if x not in secret_key]

        for i in range(25):
            self.playfair_dict_1[i+1] = playfair_alp_set[i]
            self.playfair_dict_2[playfair_alp_set[i]] = i+1

    def playfair_encrypt(self, digram):
        index_arr = [5,1,2,3,4,5,1]
        row1, row2 = ((self.playfair_dict_2[digram[i]]-1) // 5 + 1 for i in range(2))
        col1, col2 = ((self.playfair_dict_2[digram[i]]-1) % 5 + 1 for i in range(2))
        
        if row1 == row2:
            col1, col2 = index_arr[col1 + 1], index_arr[col2 + 1]
        elif col1 == col2:
            row1, row2 = index_arr[row1 + 1], index_arr[row2 + 1]
        else:
            col1, col2 = col2, col1
        
        return self.playfair_dict_1[(row1-1)*5 + col1] + self.playfair_dict_1[(row2-1)*5 + col2]

    def playfair_decrypt(self, enc_digram):
        index_arr = [5,1,2,3,4,5,1]
        row1, row2 = ((self.playfair_dict_2[enc_digram[i]]-1) // 5 + 1 for i in range(2))
        col1, col2 = ((self.playfair_dict_2[enc_digram[i]]-1) % 5 + 1 for i in range(2))
        
        if row1 == row2:
            col1, col2 = index_arr[col1 - 1], index_arr[col2 - 1]
        elif col1 == col2:
            row1, row2 = index_arr[row1 - 1], index_arr[row2 - 1]
        else:
            col1, col2 = col2, col1
        
        return self.playfair_dict_1[(row1-1)*5 + col1] + self.playfair_dict_1[(row2-1)*5 + col2]

    def encrypt(self, plaintext):
        digrams = self.preprocess(plaintext)
        return ''.join(self.playfair_encrypt(digram) for digram in digrams)
    
    def decrypt(self, encrypted):
        digrams = self.digrams(encrypted)
        return ''.join(self.playfair_decrypt(digram) for digram in digrams)

## ------------------RailFence---------------- ##

def rail_fence_encrypt(text, depth):
    rails = [[] for _ in range(depth)]
    row, direction = 0, 1
    for char in text:
        rails[row].append(char)
        row += direction
        if row == depth - 1 or row == 0:
            direction *= -1
    return ''.join(''.join(rail) for rail in rails)


def rail_fence_decrypt(ciphertext, depth):
    rail_lengths = [0] * depth
    row, direction = 0, 1
    for _ in ciphertext:
        rail_lengths[row] += 1
        row += direction
        if row == depth - 1 or row == 0:
            direction *= -1
    rails = [[] for _ in range(depth)]
    index = 0
    for i in range(depth):
        for _ in range(rail_lengths[i]):
            rails[i].append(ciphertext[index])
            index += 1
    row, direction = 0, 1
    plaintext = []
    rail_pointers = [0] * depth
    for _ in ciphertext:
        plaintext.append(rails[row][rail_pointers[row]])
        rail_pointers[row] += 1
        row += direction
        if row == depth - 1 or row == 0:
            direction *= -1
    return ''.join(plaintext)


## ------------------Combined---------------- ##
def encrypt_combined(plaintext, key, depth):
    playfair = Playfair(key)
    playfair_encrypted = playfair.encrypt(plaintext)
    return rail_fence_encrypt(playfair_encrypted, depth)


def decrypt_combined(ciphertext, key, depth):
    playfair = Playfair(key)
    rail_decrypted = rail_fence_decrypt(ciphertext, depth)
    return playfair.decrypt(rail_decrypted)


if __name__ == "__main__":
    plaintext = input("Enter plaintext: ")
    key = input("Enter Playfair key: ")
    depth = int(input("Enter Rail Fence depth (2-5): "))
    encrypted = encrypt_combined(plaintext, key, depth)
    print(f"Encrypted: {encrypted}")
    decrypted = decrypt_combined(encrypted, key, depth)
    print(f"Decrypted: {decrypted}")
