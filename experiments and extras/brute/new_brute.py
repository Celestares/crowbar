"""
LAST TEST RESULT:
Iterations   : 15018570
All timings  : [13.575928211212158, 13.581932306289673, 13.557621479034424, 13.55373740196228, 13.58551812171936]
Average time : 13.570947504043579
Passwords/s  : 1106670.701918572
"""

from time import time

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # Base 62 where a=0 and 9=61
minimum_character = 1
maximum_character = 4

total = 0
for i in range(1, maximum_character + 1):
    total += len(charset) ** i
print(f"Iterations required: {total}")  # Print total iterations required


def dec_to_charset(n, chars=charset):
        if n < len(chars):  # When the number is less than the base number
            return chars[n]
        else:
            return dec_to_charset(n // len(chars) - 1, chars) + chars[n % len(chars)]  
            # LEFT SIDE  : Divide decimal by base number to calculate the next remainder using the same function and repeat
            # RIGHT SIDE : Translate the remainder into charset (e.g. 0=a, 1=b)


new_brute_times = []
for i in range(5):

    t = time()

    password = ""
    password_dec = 0
    while len(password) <= maximum_character:
        password = dec_to_charset(password_dec)
        password_dec += 1  # Increment decimal number by 1

    new_brute_times.append(time() - t)
    print(f"New brute: {i + 1}/5 tests done")


avg_new = sum(new_brute_times) / 5
pwps_new = total / avg_new
print(f"All timings  : {new_brute_times}")
print(f"Average time : {avg_new}")
print(f"Passwords/s  : {pwps_new}")
