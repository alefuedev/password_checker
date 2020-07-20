import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        print(f'Error fetching: {res.status_code}')
    else:
        return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
      if str(h) == hash_to_check:
        return count      

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_five_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first_five_char)
    return get_password_leaks_count(response,tail) 

def main(args):

    for password in args: 
      result = pwned_api_check(password)
      if result != None:
       print(f'The password {password} is been use {result} times is a good idea to change it.')
      else:
       print(f'The password is been use 0 times.')
    return 'Done!' 

if __name__ == '__main__':
   sys.exit(main(sys.argv[1:]))

