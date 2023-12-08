# All-Bitcoin-Private-key-Table
# Lists Every Bitcoin Private Key in Hex Format, along with both p2pkh addresses.
- You can click on any Bitcoin address to check its balance.
- You can click on any Private Key Hex to check if any of its corresponding addresses have a balance.
- You can filter though either bitcoin p2pkh column by typing in what the bitcoin address might contains or you can explicitly filter (search) for the full address your looking for.
- Comlum sizes are adustable by double clicking the top of the column to veiw the full column. (If the Private Keys or Row Numbers are cut off)
# You can change the buffer size and the starting private key.
        self.buffer_size = 2000
        self.starting_point = int('0000000000000000000000000000000000000000000000000000000000000001', 16)
- Bigger buffer size = more RAM
- This does not save any data, it just loads in the amount of rows that the buffer size is set to and starts from the stated private key. (It does not have to start from 1)
- As you scroll through the list, your RAM usage should stay steady, allowing you to scroll into the abyss of Private Keys Endlessly and Visually.
# Please make any changes to build upon the code and make it better!
# I need someone to incoporate balance checking and tansaction count columns in the future.
