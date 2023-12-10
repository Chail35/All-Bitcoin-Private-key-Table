# All-Bitcoin-Private-key-Table
# Requirements
- You must pip install the modules in the requirements.txt file if you don't have them already, for the script to run properly.
# Lists Every Bitcoin Private Key in Hex Format, along with both p2pkh addresses.
- You can click on any Bitcoin Address to check its balance.
- You can click on any Private Key Hex to check if any of its corresponding addresses have a balance.
- You can filter though either bitcoin p2pkh column (columns 2,3) by typing in what the bitcoin address might contains or you can explicitly filter (search) for the full address your looking for.
- Comlum sizes are adustable by double clicking the top of the column in between where the columns meet, to veiw the full column. (If the Private Keys or Row Numbers are cut off) or you can just click and drag the column to the size you prefer
- You can specify a specific Bitcoin Address or multiple addresses (p2pkh only) in the Target Addresses.txt file and the script will be automatically searching for it in the background.
- If a target address is in the current buffer or field of view, the private key of the found target address will pop up on the screen and it will print to the terminal.
- The script is also preset to lock in the current buffer that the target address is in, so that when its found you don't accidentally scroll past it without knowing.
# You can change the buffer size and the starting private key.
        self.buffer_size = 2000
        self.starting_point = int('0000000000000000000000000000000000000000000000000000000000000001', 16)
- Bigger buffer size = more RAM
- This does not save any data, it just loads in the amount of rows that the buffer size is set to and starts from the stated private key. (It does not have to start from 1)
- As you scroll through the list, your RAM usage should stay steady, allowing you to scroll into the abyss of Private Keys Endlessly and Visually.
# Please make any changes to build upon the code and make it better!
# I need someone to incoporate balance checking and tansaction count columns in the future.
