import os
import lief
import uuid
import hashlib
from flask import Flask, jsonify, request, render_template, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads/'

def hash_file(bytes):
    return hashlib.sha256(bytes).hexdigest()

@app.route('/api/binary/scan', methods=['POST'])
def scan_binary():
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'status': 'No binary file uploaded',
            'data': {},
        }), 500

    file = request.files['file']

    if file.filename == '':
        return jsonify({
            'success': False,
            'status': 'No binary file uploaded',
            'data': {},
        }), 500

    # Save a temporary file.
    file_name = 'up_{}_{}'.format(uuid.uuid1().hex, file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
    file_hash = ''

    file.save(file_path)

    with open(file_path, 'rb') as f:
        bytes = f.read()

        # Compute the hash of the file by reading its contents.
        file_hash = hash_file(bytes)
        print(file_hash)

        # Replace the file with saved file with a name containing its hash.
        file_name = 'up_{}_{}'.format(file_hash, file.filename)
        new_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
        os.rename(file_path, new_file_path)
        file_path = new_file_path

        f.close()

    # Open the binary file.
    binary = lief.parse(file_path)

    return jsonify({
        'success': True,
        'status': None,
        'data': {
            'url': url_for('download_file', name=file_name),
            'type': binary.header.file_type.name,
            'arch': binary.header.machine_type.name,
            'hash': file_hash,
        },
    })


@app.route('/files/<name>')
def download_file(name):
    return send_from_directory(app.config['UPLOAD_FOLDER'], name)


if __name__ == '__main__':
    app.run()

    """
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
    """

