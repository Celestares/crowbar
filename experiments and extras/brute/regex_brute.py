"""
LAST TEST RESULT:
Iterations  : 13716197
Time taken  : 45.80665588378906
Passwords/s : 299436.7463714842
"""

from time import time
import string
import re

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
password_to_find = "CatHALLO6196"
regex = "[A-Z][a-z]{2}HALLO[0-9]{4}"


def old_brute(password_index):  # password_index --> [[digit, charset_used], [digit, charset_used], ...]
    for i in range(len(password_index)):
        if password_index[len(password_index) - i - 1][0] == len(password_index[len(password_index) - i - 1][1]):
            if i != len(password_index) - 1:
                password_index[len(password_index) - i - 1][0] = 0
                password_index[len(password_index) - i - 2][0] += 1
            else:
                password_index[0][0] = 0
                password_index.insert(0, 0)
                return "".join([i[1][i[0]] for i in password_index[1:]])
    return "".join(i[1][i[0]] for i in password_index)


def create_charset(r_str):  # r_str --> regex_string
    output = ""
    for letter in string.printable:
        if re.match(r_str, letter):  # If the letter matches, add it to the charset
            output += letter
    return output


def regex_reader(r_str):  # Translate regex to list [[charset, length], [charset, length],...]
    output = []
    while r_str:  # It will slowly cut component by component until the string is empty

        output.append(["", 0])  # Initialising component data [charset, length]

        if r_str[0] == "[":                                # If component start with "[", find the index of the end of component by finding "]"
            end_index = r_str.index("]")
            temp = create_charset(r_str[0:end_index + 1])  # Create the charset of whatever was encapsulated with "[" and "]"
            output[-1][0] = temp                           # Charset is stored in the component data that was just initialised
            output[-1][1] = 1                              # Length is stored, length determines the consecutive no. of characters that used the same charset
            r_str = r_str[end_index + 1:]                  # Remove the component that was read and processed

            if not r_str:  # If string is empty, skip the next operation
                break
            
            if r_str[0] == "{":                            # Sometimes component encapsulated with "[" and "]" have "{n}" at the end to determine no. of times
                                                           # to repeat the component based on "n"
                end_index = r_str.index("}")
                output[-1][1] = (int(r_str[1:end_index]))  # Length is determined by this {n}
                r_str = r_str[end_index + 1:]              # Remove it after it was read and processed
            
        else:  # Dealing with fixed characters

            end_index = r_str.find("[")                    # To determine when fixed characters end where either they are found at the end or stopped by "["
                                                           # e.g. hi[0-9], end_index is at "[", and [0-9]hi, end_index is all the way to the end
            if end_index == -1:                            # Cannot find "[", meaning is all the way at the end
                temp = r_str
                output[-1][0] = temp                       # For fixed characters, component data for length is stored as 0 to identify them as fixed
                r_str = ""                                 # Remove the componented that was read and processed
           
            else:                                          # Found "[", end_index will stop at "["
                temp = r_str[0:end_index]                  # Retrieve fixed characters from start till "["
                output[-1][0] = temp
                r_str = r_str[end_index:]                  # Remove the componented that was read and processed

    # Check for consecutive duplicated charset to combine them (e.g. dealing with regex like [A-Z][A-Z][A-Z] instead of [A-Z]{3})
    updated = True
    while updated:
        updated = False    
        for i in range(len(output) - 1):
            if output[i][0] == output[i + 1][0]:  # Check if charset is the same from the one to its right  
                output[i][1] += output[i + 1][1]  # If so, add its length to the length of current one
                del output[i + 1]                 # Delete the right side since the length is already added
                updated = True
                break                             # Since the list is updated, need to re-iterate to avoid index error
    
    return output


# Checks if regex is valid or not
try:
    re.compile(regex)
    valid = True
except re.error:
    valid = False

if valid:
    print(regex_reader(regex))
else:
    print("Regex not valid")

regex_list = regex_reader(regex)
char_count = 0
iter_required = 1
fixed = []
password_index = []
for component in regex_list:
    if component[1] == 0:
        fixed.insert(0, [component[0], char_count])
    else:
        iter_required *= len(component[0]) ** component[1]
    char_count += component[1]
    for i in range(component[1]):
        password_index.append([0, component[0]])

# print(char_count)
# print(fixed)
# print(password_index)
print(f"Iterations required: {iter_required}")

count = 0
with open("regex_brute.txt", "w") as brute_file:
    t = time()

    while len(password_index) <= char_count:

        password = old_brute(password_index)
        if len(password_index) > char_count:
            break

        for f in fixed:
            if len(password) == f[1]:       # Fixed password is at end
                password = password + f[0]
            elif f[1] == 0:                 # Fixed password is at beginning
                password = f[0] + password
            else:                           # Fixed password is in between
                password = password[:f[1]] + f[0] + password[f[1]:]
        
        brute_file.write(password + "\n")
        if password == password_to_find:
            time_taken = time() - t
            print("DONE!")
            break

        password_index[-1][0] += 1          # Increment last digit by 1
        count += 1


pwps = count / time_taken 
print(f"Time taken  : {time_taken}")
print(f"Passwords/s : {pwps}")
