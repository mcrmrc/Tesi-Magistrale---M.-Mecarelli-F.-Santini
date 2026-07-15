class CALC: 
    def checksum(data: bytes) -> int:
        """
        Calculate the Internet checksum for the given data.
        
        :param data: The data to calculate the checksum for (as bytes).
        :return: The checksum as an integer.
        """
        checksum = 0 
        # Handle odd-length data
        if len(data) % 2 != 0:
            data += b"\x00"
        # Process the data in 16-bit chunks 
        for i in range(0, len(data), 2):
            # Combine two bytes into one 16-bit word
            word = data[i] << 8
            if i + 1 < len(data):
                word += data[i + 1]
            checksum += word
            # Handle overflow by adding the carry
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        # One's complement of the result
        checksum = ~checksum & 0xFFFF
        print(f"The checksum of\n\t{data}\n\tis\n\t{checksum}") 
        return checksum 
    
    def checksumV2(data):
        checksum = 0 
        # Handle odd-length data
        if len(data) % 2 != 0:
            data += b"\x00" 
        # Calculate checksum
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i+1] 
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16 
        return (~checksum) & 0xffff
