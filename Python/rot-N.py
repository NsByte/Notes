import sys
if __name__ == '__main__':
    encodedMsg = sys.argv[1]
    n = int(sys.argv[2])
    # lets make everything lower case
    encodedMsg = encodedMsg.lower()
    decodedMsg = ''
    for char in list(encodedMsg):
        if char.isalpha():
            value = ord(char) + n
            if value > ord('z'):
                value = (value - ord('z')) + ord('a') - 1
            decodedMsg += chr(value)
        else:
            decodedMsg += char
    print decodedMsg