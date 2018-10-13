class SBox:
    def __init__(self, name, data):
        self.name = name
        self.data = data

    #Gets result from given location in the table based on the F function
    #Key is a binary string of length 4
    def getResult(self, key):
        #Converting the key into the row and col numbers
        row = int('{:}{:}'.format(key[0],key[3]), 2)
        col = int('{:}{:}'.format(key[1],key[2]), 2)
        
        #Debug print statement to check SBox values
        #print("Row: {:} | Col: {:} | Val: {:}".format(row, col, self.data[row][col]))

        #Gets the result from the table and convert it to binary
        result = bin(self.data[row][col])[2:]
        #If the result is <2, add an extra 0 in the front to keep formatting correct
        if len(result) == 1:
            result = "0"+result
        
        return(result)

    def printGrid(self):
        #Nicely printing out the SBox for debugging purposes
        print("SBox {:}".format(self.name))
        for row in self.data:
            rowText = ""
            for num in row:
                rowText += "{:} ".format(num)
            print(rowText)
        print()
