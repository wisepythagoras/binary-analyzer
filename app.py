import os
import lief
from flask import Flask, jsonify, request, render_template, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads/'

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

    file_name = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
    file.save(file_path)

    binary = lief.parse(file_path)

    return jsonify({
        'success': True,
        'status': None,
        'data': {
            'url': url_for('download_file', name=file_name),
            'type': binary.header.file_type.name,
            'arch': binary.header.machine_type.name,
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

