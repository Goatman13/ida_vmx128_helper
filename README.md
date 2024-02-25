# ida_vmx128_helper
Plugin fix misinterpreted VMX128 A register in IDA.

Features
-------

- Plugin fix misinterpreted VMX128 A register in IDA.
- Fully automatic, just throw it into IDA plugins directory and restart IDA.

Bugs
-------

- Plugin breaks autocomments for fixed opcodes (apparently ev_get_autocmt not work from plugin interface)

Example
-------

Before:
![before](https://github.com/Goatman13/ida_vmx128_helper/assets/101417270/6f900693-5998-42f7-ac5a-9f82d8078588)

After:
![after](https://github.com/Goatman13/ida_vmx128_helper/assets/101417270/b5c52c6b-865d-4d62-8f3d-ecd0a154b6a0)

