file_prepend = "origin/test3_"
for i in range(1024):
    file_name = file_prepend + str(i) + ".txt"
    with open(file_name, "w") as file:
        file.write(file_name + ": this is sample test data")

