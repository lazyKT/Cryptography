import os
import sys
from hashlib import md5


class Rainbow:
    """
    # Simplified Rainbow Table.
    # What're the differences with the real rainbow tables?
    # This class doesn't handle collision,
    # This class doesn't accept sepcific number of hash prefix
    """

    passwords = list()
    rainbow = dict()
    reduction_table = list()
    num_passwords = 0
    size = 0


    def __init__(self, filename: str):
        self.filename = filename


    def build(self):
        """
        # Building the entire Rainbow Table with password file
        """
        self.passwords = self.read_file(self.filename)
        # keep track of the used passwords
        used_pwd_idxes = list()
        self.num_passwords = len(self.passwords)
        for i in range(self.num_passwords):
            if i in used_pwd_idxes:
                continue
            idx = Rainbow.get_next_chain(self.passwords[i], self.num_passwords)
            used_pwd_idxes.append(idx-1)
            for _ in range(4):
                idx = Rainbow.get_next_chain(self.passwords[idx-1], self.num_passwords)
                # print('[DEBUG] Building Rainbow Table : {} {}'.format(self.passwords[i], Rainbow.hash(self.passwords[idx-1]).hex()))
            self.rainbow[self.passwords[i]] = Rainbow.hash(self.passwords[idx-1]).hex()\


    def construct_reduction_table(self) -> list:
        reduct_list = list()
        for pwd in self.passwords:
            h = self.hash(pwd)
            r = self.reduct(h, self.num_passwords)
            reduct_list.append('{} : {} : {}'.format(pwd, h.hex(), r))
        return reduct_list


    def read_file(self, file : str = None) -> list:
        """
        # Read file lines by lines
        """
        if file is None:
            file = self.filename
        with open (file, 'r') as f:
            for line in f:
                self.passwords.append(line.split('\n')[0])
        return self.passwords


    def save(self, target_file : str = None) -> int:
        if target_file is None or target_file == '':
            target_file = 'rainbow.txt'
        count = 0
        self.rainbow = Rainbow.sort_dict_by_value(self.rainbow)
        with open(target_file, 'w') as f:
            for k,v in self.rainbow.items():
                f.write('{} : {}\n'.format(k, v))
                count += 1
        self.size = count
        return count


    def search(self, q: str) -> str:
        """
        # Search Potential Hash Values in Password List
        """
        result = Rainbow.search_dict_by_value(self.rainbow, q)
        if result is None:
            print(info_prefix, 'hash value not found in rainbow table')
            print(info_prefix, 'performing further hashing ...')
        i = 0
        while (result is None):
            if i > self.size:
                return None
            r = self.reduct (bytes.fromhex(q), self.num_passwords)
            q = self.hash(self.passwords[r-1]).hex()
            # print(debug_prefix, 'reduction: {}, next chain: {}'.format(r, q))
            result = Rainbow.search_dict_by_value(self.rainbow, q)
            i += 1
        return result


    def search_in_chain(self, chain: str, q: str) -> str:
        """
        # Search hash values in a specific chain
        """
        print('[info] Searching in chain :', chain)
        _h = Rainbow.hash(chain)
        # print('[DEBUG]  reduct chain: {} {}'.format(chain, _h.hex()))
        if _h.hex() == q:
            return chain
        current_pwd = chain
        for _ in range(5):
            next_pwd_idx = self.get_next_chain(current_pwd, self.num_passwords)
            current_pwd = self.passwords[next_pwd_idx - 1]
            _h = Rainbow.hash(current_pwd)
            # print('[DEBUG]  reduct chain: {} {} {}'.format(next_pwd_idx, current_pwd, _h.hex()))
            if _h.hex() == q:
                return current_pwd
        return None



    def search_chains(self, q: str, pwd: str) -> str:
        """
        # Search Potential Passwords in Rainbow Table chain
        """
        # next_pwd_idx = Rainbow.get_next_chain(pwd, self.num_passwords) # index in password list
        # next_pwd = self.passwords[next_pwd_idx - 1] # plain password
        # _h = Rainbow.hash(next_pwd) # password hash
        # print('[DEBUG]  reduct chain: {} {} {}'.format(next_pwd_idx, next_pwd, _h.hex()))
        # for _ in range(5):
        #     if _h.hex() == q:
        #         return next_pwd
        #     next_pwd_idx = Rainbow.get_next_chain(next_pwd, self.num_passwords) # index in password list
        #     next_pwd = self.passwords[next_pwd_idx - 1] # plain password
        #     _h = Rainbow.hash(next_pwd) # password hash
        #     print('[DEBUG]  reduct chain: {} {} {}'.format(next_pwd_idx, next_pwd, _h.hex()))
        res = self.search_in_chain(pwd, q)
        if res:
            return res

        next_chain = self.get_next_dict(self.rainbow, pwd)
        pre_image = None
        while next_chain is not False:
            # print('[DEBUG]  advance to next chain', next_chain)
            # _h = Rainbow.hash(next_chain)
            # print('[DEBUG]  reduct chain: {} {}'.format(next_chain, _h.hex()))
            # if _h.hex() == q:
            #     return next_chain
            # next_pwd_idx = Rainbow.get_next_chain(next_chain, self.num_passwords) # index in password list
            # next_pwd = self.passwords[next_pwd_idx - 1] # plain password
            # _h = Rainbow.hash(next_pwd) # password hash
            # print('[DEBUG]  reduct chain: {} {} {}'.format(next_pwd_idx, next_pwd, _h.hex()))
            # for _ in range(4):
            #     if _h.hex() == q:
            #         return next_pwd
            #     next_pwd_idx = Rainbow.get_next_chain(next_pwd, self.num_passwords) # index in password list
            #     next_pwd = self.passwords[next_pwd_idx - 1] # plain password
            #     _h = Rainbow.hash(next_pwd) # password hash
            #     print('[DEBUG]  reduct chain: {} {} {}'.format(next_pwd_idx, next_pwd, _h.hex()))
            res = self.search_in_chain(next_chain, q)
            if res:
                return res
            next_chain = self.get_next_dict(self.rainbow, next_chain)

        return None


    def get_contents(self) -> dict:
        return self.rainbow


    def get_size(self) -> int:
        """
        # Get the size of raibow table, i.e, number of entries in rainbow table
        """
        return len(self.rainbow)


    def get_numofpasswords_read(self) -> int:
        """
        # Get Number of Passwords Read from passwd
        """
        return len(self.passwords)


    @classmethod
    def reduct(cls, h: bytes, n: int) -> int:
        """
        Simple reduction function.
        In real world, we would take the specific number of prefix characters from hash
        and there will be more than one reduction functions to handle collisions.
        However, in this script, reduction function emphasizes the simplicity and takes whole hash value.
        """
        r = int.from_bytes(h, byteorder='big')
        return (r%n) + 1


    @classmethod
    def hash(cls, w: str) -> bytes:
        m = md5()
        m.update(w.encode())
        return m.digest()


    @classmethod
    def get_next_chain(cls, word: str, n: int) -> int:
        """
        hash the plain text and find the next possible chain
        @param->word: plaintext
        @param->n: number of the passwords in files (modulo value for reduction function)
        @return: index of the next possible chain in the file
        """
        h = Rainbow.hash(word)
        return Rainbow.reduct(h, n)


    @staticmethod
    def save_file(contents: list, target_file: str):
        with open(target_file, 'w') as f:
            for c in contents:
                f.write('{}\n'.format(c))


    @staticmethod
    def sort_dict_by_value(di: dict) -> dict:
        print('[info]  Sorting Rainbow Table by Hash Values ...')
        return dict(sorted(di.items(), key=lambda kv: kv[1]))


    @staticmethod
    def sort_dict_by_value(di: dict) -> dict:
        return dict(sorted(di.items(), key=lambda kv: kv[1]))


    @staticmethod
    def search_dict_by_value(di: dict, q: str) -> str:
        """
        # Search Dictionary by value
        # return key of dictionary, related to the value
        """
        return next((k for k,v in di.items() if v == q), None)


    @staticmethod
    def get_next_dict(di, key):
        keys = iter(di)
        key in keys
        return next(keys, False)


error_prefix = '[Error] '
info_prefix = '[Info] '
debug_prefix = '[Debug] '


def get_hash_input ()-> str:
    retry = 0
    while (retry < 3):
        try:
            input_hash = (input('Please enter the hash value (32-characters hex-string) :')).strip()
            int(input_hash, 16)
            if len(input_hash) == 32:
                return input_hash
            print('{} Please enter the 32-characters hash. retry : {}'.format(error_prefix, len(input_hash)))
        except:
            print('{} Invalid hash value. Please try again. retry : {}'.format(error_prefix, len(input_hash)))
            retry += 1
    return None


def get_cmd_args():
    file_name = str((sys.argv)[1])
    if not os.path.isfile(file_name):
        print (error_prefix, "No Such file:", file_name)
        sys.exit(1)
    return file_name


def main():
    file_name = get_cmd_args()

    rainbow = Rainbow(file_name)
    rainbow.build()
    print(info_prefix, 'Number of passwords read :', rainbow.get_numofpasswords_read())
    r_table = rainbow.construct_reduction_table()
    # Rainbow.save_file(r_table, 'words-reduction.txt')
    r = rainbow.get_contents()
    print (info_prefix, 'Rainbow Table Size :', rainbow.get_size())

    print(info_prefix, 'Please enter the filename to save the rainbow table contents.')
    file_name = (str(input('Leave Blank for default name. [rainbow.txt] :'))).strip()
    rainbow.save(file_name)

    print('\n---------------------------------\n')
    _h = get_hash_input()
    # _h = str(sys.argv[2])
    if _h is None:
        print(error_prefix, 'Receiving Consecutive Error Inputs. Terminating Process ...')
        sys.exit(1)

    pre_image = rainbow.search(_h)

    if pre_image:
        print(info_prefix, 'potential hash value found in table with password', pre_image)
        print(info_prefix, 'search done. performing further reductions ...')
        pre_image = rainbow.search_chains(_h, pre_image)
        if pre_image:
            print(info_prefix, 'Hash Value Found with Pre-Image :', pre_image)
        else:
            print(info_prefix, 'Finished Searching in all chains.')
            print(info_prefix, 'Unable to find hash value :', _h)
    else:
        print (info_prefix, 'Unable to find hash value :', _h)


if __name__ == '__main__':
    main();
