# AES-128 encryption/decryption implementation
from os import urandom

class AES:

  #s_box for ecnryption
  s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, # 0
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, # 1
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, # 2
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, # 3
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, # 4
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, # 5
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, # 6
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, # 7
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, # 8
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, # 9
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, # a
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, # b
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, # c
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, # d
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, # e
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16, # f
    # 0    #1    #2    #3    #4    #5    #6.   # 7.  #8    #9.   #a.    #b.   #c.   #d.   #e.  #f
  )


  #inverse sbox for decryption
  inverse_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, # 0
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, # 1
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, # 2
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, # 3
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, # 4
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, # 5
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, # 6
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, # 7
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, # 8
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, # 9
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, # a
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, # b
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, # c
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, # d
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, # e
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D, # f
    # 0    #1    #2    #3    #4    #5    #6.   # 7.  #8    #9.   #a.    #b.   #c.   #d.   #e.  #f
  )

  # r_con
  rcon = ( 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 )

  # matrix constant
  matrix = ( 0x01, 0x01, 0x02, 0x03 )
  inv_matrix = ( 0x09, 0x0d, 0x0e, 0x0b)
  key_size = ''
  round_keys = list()
  padding_size = 0

  def __init__ (self, key_size : str = '128'):
    self.key_size = key_size
    self.round_keys = ['0x00'] * 11 # initialise buffer for key

  # generate key from string input given by user
  def set_key (self, key_str : str):
    key = key_str.encode('ascii').hex()
    while len(key) < 32:
      key += '0'
    if len(key) > 32:
      raise RuntimeError("Invalid Key: Key Size must be 128-bits")
    key_matrix = AES.to_matrix(key)
    self.key_scheduling(key_matrix)

  # generate secret random key
  def gen_key (self) -> bytes:
    key = urandom(16).hex()
    key_matrix = AES.to_matrix(key)
    self.key_scheduling(key_matrix)

  def key_scheduling (self, key:str) -> list:
    self.round_keys[0] = key
    for x in range(1,11):
      self.gen_round_key (self.round_keys[x-1], x)

  # round key scheduling: 10 rounds
  def gen_round_key (self, prev_key : list, i : int) -> str:
    fc_prv = [ prev_key[x] for x in range(16) if x%4 == 0 ]
    sc_prv = [ prev_key[x] for x in range(16) if x%4 == 1 ]
    tc_prv = [ prev_key[x] for x in range(16) if x%4 == 2 ]
    lc_prv = [ prev_key[x] for x in range(16) if x%4 == 3 ]
    temp = lc_prv.copy()
    round_key = list()
    round_key = ['0x00'] * 16
    # first column of round key
    lc_prv = AES.rotate_left(lc_prv)
    t = self.sub_bytes(lc_prv)
    for x in range(4):
      r = 0x00 if x != 0 else self.rcon[i-1]
      round_key[x*4] =  hex( int(t[x], 16) ^ r ^ int(fc_prv[x], 16) )
    # second column of round key
    fc_round = [ round_key[x] for x in range(16) if x%4 == 0]
    for x in range(4):
      round_key[x*4 + 1] = ( hex( int(sc_prv[x], 16) ^ int(fc_round[x], 16) ))
    # third column of round key
    sc_round = [ round_key[x] for x in range(16) if x%4 == 1]
    for x in range(4):
      round_key[x*4 + 2] = ( hex( int(tc_prv[x], 16) ^ int(sc_round[x], 16) ))
    # last column of round key
    tc_round = [ round_key[x] for x in range(16) if x%4 == 2]
    for x in range(4):
      round_key[x*4 + 3] = ( hex( int(temp[x], 16) ^ int(tc_round[x], 16) ))
    self.round_keys[i] = round_key


  def print_round_keys (self):
    for x in range(11):
      header = "Master Key" if x == 0 else "Key {}".format(str(x))
      print(header)
      self.print_key(self.round_keys[x])


  def print_key (self, k = None) -> list:
    if k == None:
      return
    for x in range(0, len(k), 4):
      print(k[x:x+4])
    print("\n")


  def cipher (self, mode : int, state : str) -> str:
    state = state.encode('ascii').hex() if mode == 0 else state
    # add padding if the msg is not 16bytes
    while len(state) < 32:
      self.padding_size += 1
      state += '0'
    if len(state) > 32:
      raise RuntimeError("Invalid Input: Input size must be 16-bytes!")
    # print("Input (hex) : %s" % state)
    state_matrix = AES.to_matrix(state)
    if mode == 0:
      return self.encrypt(state_matrix)
    elif mode == 1:
      return self.decrypt(state_matrix)
    else:
      raise RuntimeError(f"Invalid Cipher Mode: {str(mode)}")

  ### Encryption ###
  def encrypt (self, msg : list) -> str:
    # add round key: initial
    state = list()
    state = self.add_round_key (msg, 0)
    for i in range(1, 11):
      sb_state = self.sub_bytes(state) # subBytes
      sr_state = self.shif_row(sb_state) # shift row
      # if i < 10:
      #   print("Round {} cipher imc check : {}".format(i, self.from_matrix(sr_state)))
      mc_state = self.mix_column(sr_state) if i != 10 else sr_state.copy() # mix column
      ad_state = self.add_round_key (mc_state, i) # add round key
      # print(f"Round {i} Cipher Text")
      # self.print_key(mc_state)
      state = ad_state.copy()
      # if i < 10:
      #   print("Round {} cipher : {}".format(i, AES.from_matrix(state)))
    #self.print_key(state)
    state_str = AES.from_matrix(state)
    return state_str

  ### Decryption ###
  def decrypt (self, c : list) -> str:
    # add round key: initial
    state = self.add_round_key (c, 10)
    # print("Round 10 msg : {}".format(self.from_matrix(state)))
    for i in range(9, -1, -1):
      sr_state = self.inv_shift_row(state) # inverse shift row
      sb_state = self.sub_bytes(sr_state, mode='inverse') # inverse subBytes
      #print("Round {} msg check : {}".format(i, self.from_matrix(sb_state)))
      ad_state = self.add_round_key (sb_state, i) # add round key
      # inverse mix columns
      mc_state = self.mix_column (ad_state, mode = 'inverse') if i != 0 else ad_state.copy()
      #print("Round {} msg imc check : {}".format(i, self.from_matrix(mc_state)))
      state = mc_state.copy()
      # print("Round {} msg : {}".format(i, AES.from_matrix(state)))
    #self.print_key(state)
    state_str = AES.from_matrix (state)
    # print("Decrypted text (hex) : {}".format(state_str))
    st = AES.hex_to_str(state_str)
    pad_size = 16 - int(self.padding_size/2) # remove padding
    return st[:pad_size]


  # add round key
  def add_round_key (self, state : list, n : int) -> list:
    for x in range(16):
      state[x] = hex( int(state[x], 16) ^ int(self.round_keys[n][x], 16))
    return state

  # subBytes
  def sub_bytes (self, bs:list, mode : str = 'normal') -> list:
    ls = list()
    for b in bs:
      r = 0 if len(b) < 4 else (int(b[2], 16) * 16)
      c = int(b[2], 16) if len(b) < 4 else int(b[3], 16)
      s_byte = hex(self.s_box[ r + c]) if mode == 'normal' else hex(self.inverse_s_box[r + c])
      ls.append(s_byte)
    return ls

  # shift row : left circular shift : encryption
  def shif_row (self, state : list) -> list:
    state[4], state[5], state[6], state[7] = state[5], state[6], state[7], state[4]
    state[8], state[9], state[10], state[11] = state[10], state[11], state[8], state[9]
    state[12], state[13], state[14], state[15] = state[15], state[12], state[13], state[14]
    return state

  # inverse shift row : right circular shift row : decryption
  def inv_shift_row (self, state : list) -> list:
    state[4], state[5], state[6], state[7] = state[7], state[4], state[5], state[6]
    state[8], state[9], state[10], state[11] = state[10], state[11], state[8], state[9]
    state[12], state[13], state[14], state[15] = state[13], state[14], state[15], state[12]
    return state

  # mix column
  def mix_column (self, state : list, mode : str = 'normal') -> list:
    temp = list()
    temp = ['0x00'] * 16
    mtrx = self.matrix if mode == 'normal' else self.inv_matrix
    for i in range(0, 16, 4):
      idx = int(i/4)
      c1 = AES.multiply(int(state[idx], 16), mtrx[2]) ^ AES.multiply(int(state[idx+4], 16), mtrx[3]) ^ AES.multiply(int(state[idx+8], 16), mtrx[1]) ^ AES.multiply(int(state[idx+12], 16), mtrx[0])
      temp[idx] = hex(c1)
      c2 = AES.multiply(int(state[idx], 16), mtrx[0]) ^ AES.multiply(int(state[idx+4], 16), mtrx[2]) ^ AES.multiply(int(state[idx+8], 16), mtrx[3]) ^ AES.multiply(int(state[idx+12], 16), mtrx[1])
      temp[idx+4] = hex(c2)
      c3 = AES.multiply(int(state[idx], 16), mtrx[1]) ^ AES.multiply(int(state[idx+4], 16), mtrx[0]) ^ AES.multiply(int(state[idx+8], 16), mtrx[2]) ^ AES.multiply(int(state[idx+12], 16), mtrx[3])
      temp[idx+8] = hex(c3)
      c4 = AES.multiply(int(state[idx], 16), mtrx[3]) ^ AES.multiply(int(state[idx+4], 16), mtrx[1]) ^ AES.multiply(int(state[idx+8], 16), mtrx[0]) ^ AES.multiply(int(state[idx+12], 16), mtrx[2])
      temp[idx+12] = hex(c4)
    return temp

  def inv_mix_column (self, state : list) -> list:
    temp = list()
    temp = ['0x00'] * 16
    mtrx = ( 0x09, 0x0d, 0x0e, 0x0b)
    for i in range(0, 16, 4):
      idx = int(i/4)
      c1 = AES.multiply(int(state[idx], 16), mtrx[2]) ^ AES.multiply(int(state[idx+4], 16), mtrx[3]) ^ AES.multiply(int(state[idx+8], 16), mtrx[1]) ^ AES.multiply(int(state[idx+12], 16), mtrx[0])
      temp[idx] = hex(c1)
      c2 = AES.multiply(int(state[idx], 16), mtrx[0]) ^ AES.multiply(int(state[idx+4], 16), mtrx[2]) ^ AES.multiply(int(state[idx+8], 16), mtrx[3]) ^ AES.multiply(int(state[idx+12], 16), mtrx[1])
      temp[idx+4] = hex(c2)
      c3 = AES.multiply(int(state[idx], 16), mtrx[1]) ^ AES.multiply(int(state[idx+4], 16), mtrx[0]) ^ AES.multiply(int(state[idx+8], 16), mtrx[2]) ^ AES.multiply(int(state[idx+12], 16), mtrx[3])
      temp[idx+8] = hex(c3)
      c4 = AES.multiply(int(state[idx], 16), mtrx[3]) ^ AES.multiply(int(state[idx+4], 16), mtrx[1]) ^ AES.multiply(int(state[idx+8], 16), mtrx[0]) ^ AES.multiply(int(state[idx+12], 16), mtrx[2])
      temp[idx+12] = hex(c4)
    return temp

  # roate left
  @staticmethod
  def rotate_left (row : list):
    row[0], row[1], row[2], row[3] = row[1], row[2], row[3], row[0]
    return row

  # from linear list to 4x4 matrix
  @staticmethod
  def to_matrix (state : str) -> list:
    key_matrix = list()
    key_matrix = ['0x00'] * 16 # initialise list of 16 elements
    i = 0
    for x in range(0,32,2):
      if state[x:x+2] != '00':
        idx = int ((i%4) * 4) + int(i/4)
        key_matrix[idx] = hex(int(state[x:x+2], 16))
      i += 1
    return key_matrix

  # from 4x4 matrix to str
  @staticmethod
  def from_matrix (matrix : list) -> str:
    state = list()
    state = ['00'] * 16
    i = 0
    for x in range(16):
      st = matrix[x][2:] if len(matrix[x]) == 4 else f"0{matrix[x][2]}"
      idx = (int(i%4) * 4) + int(i/4)
      state[idx] = st
      i += 1
    return "".join(state)

  # hexstring to plainstring
  @staticmethod
  def hex_to_str (hstr : str) -> str:
    st = ''
    for x in range(0,32, 2):
      st += bytearray.fromhex(hstr[x:x+2]).decode()
    return st

  # galois field (2^n) multiply
  # This method is referenced from Wikipedia Rijndael Galos Field in C language
  @staticmethod
  def multiply (a, b):
    res = 0
    while a and b:
      if b & 1:
        res = res ^ a
      if a & 0x80:
        a = ( a << 1 ) ^ 0x11b
      else:
        a = a << 1
      b = b >> 1
    return res


def main ():
  ENCRYPT_MODE = 0
  DECRYPT_MODE = 1
  plaintext = input('Enter message to encrypt : ')
  print("Plaintext (str) : %s" % plaintext)
  aes = AES()
  aes.set_key("Thats my Kung Fu")
  # aes.print_round_keys()
  e = aes.cipher(ENCRYPT_MODE, plaintext)
  print("Cipher Text : %s" % e)
  m = aes.cipher(DECRYPT_MODE, e)
  print("Plain Text : %s" % m)

# main
if __name__ == "__main__":
  main()
