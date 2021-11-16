# Test Regex functionality

import string
import re

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
password_to_find = "CatHALLO6196"
regex = "[A-Z][a-z]{2}HALLO[0-9]{4}"


def old_brute(password_index):
    for i in range(len(password_index)):
        if password_index[len(password_index) - i - 1][0] == len(password_index[len(password_index) - i - 1][1]):
            if i != len(password_index) - 1:  # If it is not the last iteration
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
        if re.match(r_str, letter):
            output += letter
    return output


def regex_reader(r_str):  # Translate regex to list [[charset, len], [charset, len],...]
    output = []
    while r_str:

        output.append(["", 0])

        if r_str[0] == "[":
            end_index = r_str.index("]")
            temp = create_charset(r_str[0:end_index + 1])
            output[-1][0] = temp
            output[-1][1] = 1
            r_str = r_str[end_index + 1:]

            if r_str[0] == "{":
                end_index = r_str.index("}")
                output[-1][1] = (int(r_str[1:end_index]))
                r_str = r_str[end_index + 1:]
            
        else:

            end_index = r_str.find("[")

            if end_index == -1:
                temp = r_str
                output[-1][0] = temp
                r_str = ""
           
            else:
                temp = r_str[0:end_index]
                output[-1][0] = temp
                r_str = r_str[end_index:]

    # Check for consecutive duplicated charset (to combine them)
    updated = True
    while updated:
        updated = False    
        for i in range(len(output) - 1):
            if output[i][0] == output[i + 1][0]:
                output[i][1] += output[i + 1][1]
                del output[i + 1]
                updated = True
                break  # Since the list is updated, need to re-iterate to avoid index error
    
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
print(iter_required)

with open("regex_brute.txt", "w") as brute_file:
    while len(password_index) <= char_count:

        password = old_brute(password_index)
        if len(password_index) > char_count:
            break

        for f in fixed:
            if len(password) == f[1]:  # Fixed password is at end
                password = password + f[0]
            elif f[1] == 0:  # Fixed password is at beginning
                password = f[0] + password
            else:  # Fixed password is in between
                password = password[:f[1]] + f[0] + password[f[1]:]
        
        brute_file.write(password + "\n")
        if password == password_to_find:
            print("DONE!")
            break

        password_index[-1][0] += 1
