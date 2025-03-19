package pop

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/babylonlabs-io/babylon/crypto/bip322"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/urfave/cli"

	"github.com/babylonlabs-io/btc-staker/babylonclient/keyringcontroller"
	"github.com/babylonlabs-io/btc-staker/cmd/stakercli/helpers"
	"github.com/babylonlabs-io/btc-staker/staker"
	ut "github.com/babylonlabs-io/btc-staker/utils"
)

const (
	msgFlag                 = "msg"
	btcNetworkFlag          = "btc-network"
	btcWalletHostFlag       = "btc-wallet-host"
	btcWalletRPCUserFlag    = "btc-wallet-rpc-user"
	btcWalletRPCPassFlag    = "btc-wallet-rpc-pass"
	btcWalletNameFlag       = "btc-wallet-name"
	btcWalletPassphraseFlag = "btc-wallet-passphrase"
	btcAddressFlag          = "btc-address"
	babyAddressFlag         = "baby-address"
	babyAddressPrefixFlag   = "baby-address-prefix"
	keyringDirFlag          = "keyring-dir"
	keyringBackendFlag      = "keyring-backend"
	outputFileFlag          = "output-file"
)

var PopCommands = []cli.Command{
	{
		Name:     "pop",
		Usage:    "Commands about proof-of-possession generation and verification",
		Category: "PoP commands",
		Subcommands: []cli.Command{
			GenerateCreatePopCmd,
			generateDeletePopCmd,
			signCosmosAdr36Cmd,
			ValidatePopCmd,
		},
	},
}

var GenerateCreatePopCmd = cli.Command{
	Name:      "generate-create-pop",
	ShortName: "gcp",
	Usage:     "stakercli pop generate-create-pop",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     babyAddressFlag,
			Usage:    "Baby address to generate proof of possession for",
			Required: true,
		},
		cli.StringFlag{
			Name:  babyAddressPrefixFlag,
			Usage: "Baby address prefix",
			Value: "bbn",
		},
		cli.StringFlag{
			Name:  btcNetworkFlag,
			Usage: "Bitcoin network on which staking should take place (testnet3, mainnet, regtest, simnet, signet)",
			Value: "testnet3",
		},
		cli.StringFlag{
			Name:  "btc-signature",
			Usage: "Base64-encoded Schnorr signature of the Babylon address. If not provided, the tool will print the data to be signed and exit.",
		},
		cli.StringFlag{
			Name:     "btc-pubkey",
			Usage:    "Hex-encoded 32-byte X-only Bitcoin public key. Required for both signing and verification.",
			Required: true,
		},
		cli.StringFlag{
			Name:  keyringDirFlag,
			Usage: "Keyring directory",
			Value: "",
		},
		cli.StringFlag{
			Name:  keyringBackendFlag,
			Usage: "Keyring backend",
			Value: "test",
		},
		cli.StringFlag{
			Name:  outputFileFlag,
			Usage: "Path to output JSON file",
			Value: "",
		},
	},
	Action: generatePop,
}

func generatePop(c *cli.Context) error {
	network := c.String(btcNetworkFlag)

	networkParams, err := ut.GetBtcNetworkParams(network)
	if err != nil {
		return err
	}

	// Get BTC pubkey and convert to P2TR address
	btcPubKeyHex := c.String("btc-pubkey")
	if btcPubKeyHex == "" {
		return fmt.Errorf("btc-pubkey is required")
	}

	btcPubKeyBytes, err := hex.DecodeString(btcPubKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode Bitcoin public key: %w", err)
	}

	// Only accept 32-byte X-only public keys
	if len(btcPubKeyBytes) != 32 {
		return fmt.Errorf("invalid public key format: only 32-byte X-only public keys are supported")
	}

	// Create Taproot key and address
	internalKey, err := schnorr.ParsePubKey(btcPubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse Bitcoin public key from X-only key: %w", err)
	}
	btcAddress, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(internalKey), networkParams)
	if err != nil {
		return fmt.Errorf("failed to create Taproot address from public key: %w", err)
	}

	// Store the btcPubKey for later use
	btcPubKey := internalKey

	babylonAddress := c.String(babyAddressFlag)
	babyAddressPrefix := c.String(babyAddressPrefixFlag)

	sdkAddressBytes, err := sdk.GetFromBech32(babylonAddress, babyAddressPrefix)
	if err != nil {
		return fmt.Errorf("failed to decode baby address: %w", err)
	}

	sdkAddress := sdk.AccAddress(sdkAddressBytes)

	keyringDir := c.String(keyringDirFlag)
	keyringBackend := c.String(keyringBackendFlag)

	keyring, err := keyringcontroller.CreateKeyring(keyringDir, "babylon", keyringBackend, nil)
	if err != nil {
		return err
	}

	record, babyPubKey, err := staker.GetBabyPubKey(keyring, sdkAddress)
	if err != nil {
		return err
	}

	// Prepare BIP322 transaction data to be signed
	bech32cosmosAddressString, err := sdk.Bech32ifyAddressBytes(babyAddressPrefix, sdkAddress.Bytes())
	if err != nil {
		return fmt.Errorf("failed to get babylon address bytes: %w", err)
	}

	// The message we want to sign is the normalized babylon address
	msg := []byte(bech32cosmosAddressString)

	// Create a BIP322 toSpend tx
	toSpendTx, err := bip322.GetToSpendTx(msg, btcAddress)
	if err != nil {
		return fmt.Errorf("failed to create BIP322 toSpend transaction: %w", err)
	}

	// Get the toSign tx that will be signed
	toSignTx := bip322.GetToSignTx(toSpendTx)

	// If no BTC signature is provided, print the data to be signed and exit
	btcSignature := c.String("btc-signature")
	if btcSignature == "" {
		// Prepare fetcher for signature hash
		fetcher := txscript.NewCannedPrevOutputFetcher(
			toSpendTx.TxOut[0].PkScript, 0,
		)

		// Create sig hash cache
		hashCache := txscript.NewTxSigHashes(toSignTx, fetcher)

		// For P2TR, use SigHashDefault signature type
		sigHash, err := txscript.CalcTaprootSignatureHash(
			hashCache,
			txscript.SigHashDefault,
			toSignTx,
			0,
			fetcher,
		)
		if err != nil {
			return fmt.Errorf("failed to calculate witness signature hash: %w", err)
		}

		// Prepare instructions with BIP322 info
		fmt.Println("Message to be signed (normalized Babylon address):")
		fmt.Println(bech32cosmosAddressString)
		fmt.Println("\nDerived Bitcoin address:")
		fmt.Println(btcAddress.String())
		fmt.Println("\nSignature hash to be signed (base64) (COPY THIS AND SIGN IT):")
		fmt.Println(base64.StdEncoding.EncodeToString(sigHash))
		fmt.Println("\nAfter signing this hash with your Schnorr private key:")
		fmt.Println("Pass back the base64-encoded Schnorr signature with --btc-signature flag")
		return nil
	}

	// Decode the signature
	btcSignatureBytes, err := base64.StdEncoding.DecodeString(btcSignature)
	if err != nil {
		return fmt.Errorf("failed to decode base64 signature: %w", err)
	}

	// Parse the signature as Schnorr
	schnorrSignature, err := schnorr.ParseSignature(btcSignatureBytes)
	if err != nil {
		return fmt.Errorf("failed to parse Schnorr signature: %w", err)
	}

	// Create a BIP322 witness with Schnorr signature
	witness := wire.TxWitness{
		schnorrSignature.Serialize(), // Schnorr signature
	}
	toSignTx.TxIn[0].Witness = witness

	// Serialize the signed transaction
	var buf bytes.Buffer
	if err := toSignTx.Serialize(&buf); err != nil {
		return fmt.Errorf("failed to serialize signed transaction: %w", err)
	}

	serializedTx, err := bip322.SerializeWitness(witness)
	if err != nil {
		return fmt.Errorf("failed to serialize witness: %w", err)
	}

	// Base64 encode the serialized transaction
	btcSignBabyEncoded := base64.StdEncoding.EncodeToString(serializedTx)

	if err := bip322.Verify(msg, witness, btcAddress, networkParams); err != nil {
		return fmt.Errorf("invalid BIP322 signature: %w", err)
	}

	// If we got here, the signature is valid. Continue with creating the POP
	babySignBTCAddress, err := staker.SignCosmosAdr36(
		keyring,
		record.Name,
		babylonAddress,
		[]byte(btcAddress.String()),
	)

	if err != nil {
		return fmt.Errorf("failed to sign btc address: %w", err)
	}

	popResponse := &staker.Response{
		BabyAddress:   babylonAddress,
		BTCAddress:    btcAddress.String(),
		BTCPublicKey:  hex.EncodeToString(btcPubKey.SerializeCompressed()[1:]),
		BTCSignBaby:   btcSignBabyEncoded,
		BabySignBTC:   base64.StdEncoding.EncodeToString(babySignBTCAddress),
		BabyPublicKey: base64.StdEncoding.EncodeToString(babyPubKey.Bytes()),
	}

	if outputPath := c.String(outputFileFlag); outputPath != "" {
		// Convert response to JSON
		jsonBytes, err := json.MarshalIndent(popResponse, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal response to JSON: %w", err)
		}

		// Write to file
		if err := os.WriteFile(outputPath, jsonBytes, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
	}

	helpers.PrintRespJSON(popResponse)

	return nil
}

var ValidatePopCmd = cli.Command{
	Name:      "validate",
	ShortName: "vp",
	Usage:     "stakercli pop validate <path-to-pop.json>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  btcNetworkFlag,
			Usage: "Bitcoin network (testnet3, mainnet, regtest, simnet, signet)",
			Value: "testnet3",
		},
		cli.StringFlag{
			Name:  babyAddressPrefixFlag,
			Usage: "Baby address prefix",
			Value: "bbn",
		},
	},
	Action:    validatePop,
	ArgsUsage: "<path-to-pop.json>",
}

func validatePop(c *cli.Context) error {
	if c.NArg() != 1 {
		return fmt.Errorf("expected 1 argument (pop file path), got %d", c.NArg())
	}

	// Read and parse the PoP file
	popFilePath := c.Args().First()
	popFileBytes, err := os.ReadFile(popFilePath)
	if err != nil {
		return fmt.Errorf("failed to read pop file: %w", err)
	}

	var popResponse staker.Response
	if err := json.Unmarshal(popFileBytes, &popResponse); err != nil {
		return fmt.Errorf("failed to parse pop file: %w", err)
	}

	// Get network params
	network := c.String(btcNetworkFlag)
	networkParams, err := ut.GetBtcNetworkParams(network)
	if err != nil {
		return fmt.Errorf("failed to get btc network params: %w", err)
	}

	babyAddressPrefix := c.String(babyAddressPrefixFlag)

	err = ValidatePop(popResponse, networkParams, babyAddressPrefix)
	if err != nil {
		return fmt.Errorf("pop validation failed: %w", err)
	}

	fmt.Println("Proof of Possession is valid!")

	return nil
}

func ValidatePop(popResponse staker.Response, btcNetParams *chaincfg.Params, babyPrefix string) error {
	err := ValidateBTCSignBaby(popResponse.BTCAddress, popResponse.BabyAddress, popResponse.BTCSignBaby, babyPrefix, btcNetParams)
	if err != nil {
		return fmt.Errorf("invalid btcSignBaby: %w", err)
	}

	err = ValidateBabySignBTC(popResponse.BabyPublicKey, popResponse.BabyAddress, popResponse.BTCAddress, popResponse.BabySignBTC)
	if err != nil {
		return fmt.Errorf("invalid babySignBtc: %w", err)
	}

	return nil
}

func ValidateBTCSignBaby(btcAddr, babyAddr, btcSignBaby, babyPrefix string, btcNetParams *chaincfg.Params) error {
	btcAddress, err := btcutil.DecodeAddress(btcAddr, btcNetParams)
	if err != nil {
		return fmt.Errorf("failed to decode bitcoin address: %w", err)
	}

	sdkAddressBytes, err := sdk.GetFromBech32(babyAddr, babyPrefix)
	if err != nil {
		return fmt.Errorf("failed to decode baby address: %w", err)
	}

	sdkAddress := sdk.AccAddress(sdkAddressBytes)

	bech32cosmosAddressString, err := sdk.Bech32ifyAddressBytes(babyPrefix, sdkAddress.Bytes())
	if err != nil {
		return fmt.Errorf("failed to get babylon address bytes: %w", err)
	}

	// Try to decode signature as base64
	sigBytes, err := base64.StdEncoding.DecodeString(btcSignBaby)
	if err != nil {
		// If base64 decoding fails, try hex as fallback for backward compatibility
		sigBytes, err = hex.DecodeString(btcSignBaby)
		if err != nil {
			return fmt.Errorf("failed to decode btcSignBaby (tried both base64 and hex): %w", err)
		}
	}

	// Parse the signature as Schnorr
	signature, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("failed to parse as Schnorr signature: %w", err)
	}

	// Create a proper BIP322 witness
	witness := wire.TxWitness{
		signature.Serialize(), // Schnorr signature
		{},                    // Empty control block for Taproot key path spending
	}

	// Verify the signature
	return bip322.Verify(
		[]byte(bech32cosmosAddressString),
		witness,
		btcAddress,
		btcNetParams,
	)
}

func ValidateBabySignBTC(babyPk, babyAddr, btcAddress, babySigOverBTCPk string) error {
	babyPubKeyBz, err := hex.DecodeString(babyPk)
	if err != nil {
		return fmt.Errorf("failed to decode babyPublicKey: %w", err)
	}

	babyPubKey := &secp256k1.PubKey{
		Key: babyPubKeyBz,
	}

	babySignBTC := []byte(btcAddress)
	hexBytes := hex.EncodeToString(babySignBTC)
	babySignBtcDoc := staker.NewCosmosSignDoc(babyAddr, hexBytes)
	babySignBtcMarshaled, err := json.Marshal(babySignBtcDoc)
	if err != nil {
		return fmt.Errorf("failed to marshalling cosmos sign doc: %w", err)
	}

	babySignBtcBz := sdk.MustSortJSON(babySignBtcMarshaled)

	secp256SigHex, err := hex.DecodeString(babySigOverBTCPk)
	if err != nil {
		return fmt.Errorf("failed to decode babySignBTC: %w", err)
	}

	if !babyPubKey.VerifySignature(babySignBtcBz, secp256SigHex) {
		return fmt.Errorf("invalid babySignBtc")
	}

	return nil
}

var generateDeletePopCmd = cli.Command{
	Name:      "generate-delete-pop",
	ShortName: "gdp",
	Usage:     "stakercli pop generate-delete-pop",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     btcAddressFlag,
			Usage:    "Bitcoin address to delete proof of possession for",
			Required: true,
		},
		cli.StringFlag{
			Name:     babyAddressFlag,
			Usage:    "Baby address to delete proof of possession for",
			Required: true,
		},
		cli.StringFlag{
			Name:     msgFlag,
			Usage:    "message to sign",
			Required: true,
		},
		cli.StringFlag{
			Name:  babyAddressPrefixFlag,
			Usage: "Baby address prefix",
			Value: "bbn",
		},
		cli.StringFlag{
			Name:  btcNetworkFlag,
			Usage: "Bitcoin network on which staking should take place (testnet3, mainnet, regtest, simnet, signet)",
			Value: "testnet3",
		},
		cli.StringFlag{
			Name:  keyringDirFlag,
			Usage: "Keyring directory",
			Value: "",
		},
		cli.StringFlag{
			Name:  keyringBackendFlag,
			Usage: "Keyring backend",
			Value: "test",
		},
	},
	Action: generateDeletePop,
}

type DeletePopPayload struct {
	BabyAddress   string `json:"babyAddress"`
	BabySignature string `json:"babySignature"`
	BabyPublicKey string `json:"babyPublicKey"`
	BtcAddress    string `json:"btcAddress"`
}

func generateDeletePop(c *cli.Context) error {
	network := c.String(btcNetworkFlag)

	networkParams, err := ut.GetBtcNetworkParams(network)
	if err != nil {
		return err
	}

	btcAddress, err := btcutil.DecodeAddress(c.String(btcAddressFlag), networkParams)
	if err != nil {
		return fmt.Errorf("failed to decode bitcoin address: %w", err)
	}

	babylonAddress := c.String(babyAddressFlag)
	babyAddressPrefix := c.String(babyAddressPrefixFlag)

	sdkAddressBytes, err := sdk.GetFromBech32(babylonAddress, babyAddressPrefix)
	if err != nil {
		return fmt.Errorf("failed to decode baby address: %w", err)
	}

	sdkAddress := sdk.AccAddress(sdkAddressBytes)

	keyringDir := c.String(keyringDirFlag)
	keyringBackend := c.String(keyringBackendFlag)

	keyring, err := keyringcontroller.CreateKeyring(keyringDir, "babylon", keyringBackend, nil)
	if err != nil {
		return err
	}

	record, babyPubKey, err := staker.GetBabyPubKey(keyring, sdkAddress)
	if err != nil {
		return err
	}

	msg := c.String(msgFlag)

	// We are assuming we are receiving string literal with escape characters
	interpretedMsg, err := strconv.Unquote(`"` + msg + `"`)
	if err != nil {
		return err
	}

	signature, err := staker.SignCosmosAdr36(
		keyring,
		record.Name,
		sdkAddress.String(),
		[]byte(interpretedMsg),
	)

	if err != nil {
		return err
	}

	payload := DeletePopPayload{
		BabyAddress:   sdkAddress.String(),
		BabySignature: hex.EncodeToString(signature),
		BabyPublicKey: hex.EncodeToString(babyPubKey.Bytes()),
		BtcAddress:    btcAddress.String(),
	}

	helpers.PrintRespJSON(payload)

	return nil
}

type SignatureResponse struct {
	BabyAddress   string `json:"babyAddress"`
	BabySignature string `json:"babySignature"`
	BabyPublicKey string `json:"babyPublicKey"`
}

var signCosmosAdr36Cmd = cli.Command{
	Name:      "sign-cosmos-adr36",
	ShortName: "sc",
	Usage:     "stakercli pop sign-cosmos-adr36",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     babyAddressFlag,
			Usage:    "Baby address for which signature is to be generated",
			Required: true,
		},
		cli.StringFlag{
			Name:     msgFlag,
			Usage:    "message to sign",
			Required: true,
		},
		cli.StringFlag{
			Name:  babyAddressPrefixFlag,
			Usage: "Baby address prefix",
			Value: "bbn",
		},
		cli.StringFlag{
			Name:  keyringDirFlag,
			Usage: "Keyring directory",
			Value: "",
		},
		cli.StringFlag{
			Name:  keyringBackendFlag,
			Usage: "Keyring backend",
			Value: "test",
		},
	},
	Action: signCosmosAdr36,
}

func signCosmosAdr36(c *cli.Context) error {
	babylonAddress := c.String(babyAddressFlag)
	babyAddressPrefix := c.String(babyAddressPrefixFlag)

	sdkAddressBytes, err := sdk.GetFromBech32(babylonAddress, babyAddressPrefix)
	if err != nil {
		return fmt.Errorf("failed to decode baby address: %w", err)
	}

	sdkAddress := sdk.AccAddress(sdkAddressBytes)

	keyringDir := c.String(keyringDirFlag)

	keyringBackend := c.String(keyringBackendFlag)

	keyring, err := keyringcontroller.CreateKeyring(keyringDir, "babylon", keyringBackend, nil)
	if err != nil {
		return err
	}

	record, babyPubKey, err := staker.GetBabyPubKey(keyring, sdkAddress)
	if err != nil {
		return err
	}

	msg := c.String(msgFlag)

	// We are assuming we are receiving string literal with escape characters
	interpretedMsg, err := strconv.Unquote(`"` + msg + `"`)
	if err != nil {
		return err
	}

	signature, err := staker.SignCosmosAdr36(
		keyring,
		record.Name,
		sdkAddress.String(),
		[]byte(interpretedMsg),
	)

	if err != nil {
		return err
	}

	response := SignatureResponse{
		BabyAddress:   sdkAddress.String(),
		BabySignature: hex.EncodeToString(signature),
		BabyPublicKey: hex.EncodeToString(babyPubKey.Bytes()),
	}

	helpers.PrintRespJSON(response)

	return nil
}
