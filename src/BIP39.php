<?php
declare(strict_types=1);
/**
 * @author Geoff Davis <gef.davis@gmail.com>
 */

namespace BIP39;

use InvalidArgumentException;

class BIP39
{
    private const WORD_LIST_SIZE = 2048;
    private const VALID_STRENGTH = [128, 160, 192, 224, 256];
    private const VALID_BYTE_LENGTH = [16, 20, 24, 28, 32];
    private const VALID_MNEMONIC_LENGTH = [12, 15, 18, 21, 24];

    private string $listName;
    private static array $words = [];

    public function __construct(string $wordlistFile)
    {
        $this->listName = \basename($wordlistFile);
        if (!\file_exists($wordlistFile)) {
            throw new InvalidArgumentException('Word list file not found: ' . $wordlistFile);
        }
        if (!isset(self::$words[$this->listName]) && \file_exists($wordlistFile)) {
            $wordlist = \file($wordlistFile);
            if (\count($wordlist) !== self::WORD_LIST_SIZE) {
                throw new InvalidArgumentException(
                    \sprintf('Given word list file must contain %d words', self::WORD_LIST_SIZE)
                );
            }
            self::$words[$this->listName] = \array_map('trim', $wordlist);
        }
    }

    public static function validateStrength(int $strength) : void
    {
        if (!\in_array($strength, self::VALID_STRENGTH, true)) {
            throw new InvalidArgumentException(
                "Strength '{$strength}' is invalid."
                . ' Strength must be one of the following: '
                . \implode(', ', self::VALID_STRENGTH)
            );
        }
    }

    public static function validateMnemonicLength(array $mnemonic) : void
    {
        $count = \count($mnemonic);
        if (!\in_array($count, self::VALID_MNEMONIC_LENGTH, true)) {
            throw new InvalidArgumentException(
                "Mnemonic word count '{$count}' is invalid."
                . ' Word count must be on of the following: '
                . \implode(', ', self::VALID_MNEMONIC_LENGTH)
            );
        }
    }

    public static function validateByteLength(string $bytes) : void
    {
        $length = \strlen(\hex2bin($bytes));
        if (!\in_array($length, self::VALID_BYTE_LENGTH, true)) {
            throw new InvalidArgumentException(
                "Mnemonic byte length '{$length}' is invalid."
                . ' Length must be one of the following: '
                . \implode(', ', self::VALID_BYTE_LENGTH)
            );
        }
    }

    protected function get_word(int $index) : string
    {
        return self::$words[$this->listName][$index] ?? "ERROR[{$index}]";
    }

    protected function get_word_index(string $word) : ?int
    {
        return \array_search($word, self::$words[$this->listName], true) ?? null;
    }

    /**
     * @throws \InvalidArgumentException if the strength value is invalid
     * @throws \Exception if random bytes could not be generated
     */
    public function generate(int $strength = 128) : array
    {
        $this->validateStrength($strength);
        $mnemonic = $this->to_mnemonic($this->random_bytes($strength / 8));

        return \explode(' ', $mnemonic);
    }

    /**
     * @param int $byteCount
     * @return string
     * @throws \Exception if random bytes could not be generated
     */
    protected function random_bytes(int $byteCount) : string
    {
        return \bin2hex(\random_bytes($byteCount));
    }

    protected function hex_binary(string $bytes) : string
    {
        return \implode(\array_map(function($b) {
            $bits = \base_convert($b, 16, 2);
            return \str_pad($bits, 8, '0', STR_PAD_LEFT);
        }, \str_split($bytes, 2)));
    }

    protected function checksum(string $bytes, int $bits) : string
    {
        $hash = \hash('sha256', \hex2bin($bytes), false);
        $binary = \base_convert(\substr($hash, 0, 2), 16, 2);
        $padded = \str_pad($binary, 8, '0', STR_PAD_LEFT);

        return \substr($padded, 0, $bits);
    }

    public function to_mnemonic(string $entropyBytes) : string
    {
        $this->validateByteLength($entropyBytes);

        $entropyBits = \strlen($entropyBytes) * 4;
        $checksumBits = $entropyBits / 32;

        $bits = $this->hex_binary($entropyBytes)
            . $this->checksum($entropyBytes, $checksumBits);

        $words = [];
        foreach (\str_split($bits, 11) as $index) {
            $words[] = $this->get_word(\bindec($index));
        }

        return \implode(' ', $words);
    }

    public function to_entropy(string $words) : string
    {
        $this->validateMnemonicLength(\explode(' ', $words));
        $wordArray = \explode(' ', $words);

        $bits = \array_map(function($w) {
            $index = $this->get_word_index($w);
            return \str_pad(\base_convert(\strval($index), 10, 2), 11, '0', STR_PAD_LEFT);
        }, $wordArray);

        $checksumBits = \count($wordArray) / 3;
        $entropyBits = \substr(\implode($bits), 0, -$checksumBits);
        $checksum = \substr(\implode($bits), -$checksumBits);

        $hex = \array_map(function($b) {
            return \str_pad(\base_convert($b, 2, 16), 2, '0', 0);
        }, \str_split($entropyBits, 8));

        $entropy = \implode($hex);

        if ($this->checksum($entropy, $checksumBits) !== $checksum) {
            throw new \InvalidArgumentException('Checksum failed.');
        }

        return $entropy;
    }
}
