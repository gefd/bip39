PHP BIP39 Mnemonic Implementation

Usage:
```php
    require(__DIR__ . '/src/BIP39.php');

    // Generate a Mnemonic
    $wordlist = __DIR__ . '/wordlists/english.txt';
    $bip39 = new BIP39\BIP39($wordlist);
    // Produces an array of english words that may be used as a BIP39 mnemonic
    $words = $bip39->generate();

    // entropy...
    $entropy = $bip39->to_entropy(\implode(' ', $words));

    // Produce a list of space separated english words from the given entropy
    // The mnemonic produced, should match the mnemonic words used to create the
    // entropy value.
    $words = $bip39->to_mnemonic($entropy);
```

