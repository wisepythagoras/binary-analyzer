import lief

binary = lief.parse('/bin/bash')

print('Type:', binary.header.file_type.name)
print('Entry point:', binary.header.entrypoint)

print('Functions:')

for f in binary.functions:
    name = f.name

    if name is None or name is '':
        name = '<no_name>'

    print(' - @{}: {}()'.format(f.address, name))

print('Sections:')

for s in binary.sections:
    if s.name is '' or s.size is 0:
        continue

    print(' -', s.name, s.size)

print('Relocations:')

for r in binary.relocations:
    print(r)

