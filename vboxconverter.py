#! /Users/jimmy/Documents/Code/volatility/bin/python

import sys
import struct

if len(sys.argv) != 2:
	print "Usage: " + sys.argv[0] + " <filename>"
	sys.exit(1)

f = open(sys.argv[1], 'r+b')

print "\n-------------------------------------\n"

file_header = f.read(5)
if file_header != '\x7fELF\x02':
	print "This does not appear to be a 64-bit ELF core dump, based on the file header.\n"
	sys.exit(2)


# Seek to e_phoff - should always be 0x40 for any 64-bit ELF
f.seek(32)
# Read 4 bytes, size of e_phoff
e_phoff_str = f.read(4)
# Convert the e_phoff value into an int
e_phoff_int = struct.unpack("<i", e_phoff_str)[0]

# Seek ahead to e_phnum (previous position is absolute unless 'whence' parameter is set)
f.seek(56)
# Read 2 bytes, size of e_phnum
e_phnum_str = f.read(2)
# Convert the e_phoff value into an int
e_phnum_int = struct.unpack("<h", e_phnum_str)[0]

print "e_phoff:\t\t" + str(e_phoff_int)
print "e_phnum:\t\t" + str(e_phnum_int)

offset = e_phoff_int

for i in range (e_phnum_int):

	print "\n-------------------------------------\n"
	print "Prog. Header:\t\t\t" + str(i)

	# Read next program header from file, using offset + program header number * index number
	f.seek(offset + (i * 56))
	prog_header_bin = f.read(56)
	print "Prog. Header Binary:\n" + ':'.join(x.encode('hex') for x in prog_header_bin) + "\n"

	# Parse p_type
	p_type_str = prog_header_bin[:4]
	p_type_int = struct.unpack("<I", p_type_str)[0]
	print "Prog. Header p_type:\t\t" + str(p_type_int)

	# Parse p_vaddr
	p_vaddr_str = prog_header_bin[16:24]
	p_vaddr_int = struct.unpack("<Q", p_vaddr_str)[0]
	print "Prog. Header p_vaddr:\t\t" + str(p_vaddr_int)

	# Parse p_filesz
	p_filesz_str = prog_header_bin[32:40]
	p_filesz_int = struct.unpack("<Q", p_filesz_str)[0]
	print "Prog. Header p_filesz:\t\t" + str(p_filesz_int)

	# Parse p_memsz
	p_memsz_str = prog_header_bin[40:48]
	p_memsz_int = struct.unpack("<Q", p_memsz_str)[0]
	print "Prog. Header p_memsz:\t\t" + str(p_memsz_int)


	# If a program header is found to have a p_vaddr less than 4096, re-write a new size
	if p_vaddr_int < 4096:

		print "Found a p_vaddr less than 4096"

		# Replace odl p_vaddr with "31337"
		new_p_vaddr_str = struct.pack("<Q", 31337)
		f.seek(offset + (i * 56) + 16)
		f.write(new_p_vaddr_str)

		# Print change fot confirmation
		f.seek(offset + (i * 56))
		prog_header_bin = f.read(56)
		print "Prog. Header Binary:\n" + ':'.join(x.encode('hex') for x in prog_header_bin) + "\n"

