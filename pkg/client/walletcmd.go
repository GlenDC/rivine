package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/bgentry/speakeasy"
	"github.com/spf13/cobra"

	"github.com/rivine/rivine/api"
	"github.com/rivine/rivine/modules"
	"github.com/rivine/rivine/types"
)

var (
	walletCmd = &cobra.Command{
		Use:   "wallet",
		Short: "Perform wallet actions",
		Long:  "Generate a new address, send coins to another wallet, or view info about the wallet.",
		Run:   Wrap(walletbalancecmd),
	}

	walletBlockStakeStatCmd = &cobra.Command{
		Use:   "blockstakestat",
		Short: "Get the stats of the blockstake",
		Long:  "Gives all the statistical info of the blockstake.",
		Run:   Wrap(walletblockstakestatcmd),
	}

	walletAddressCmd = &cobra.Command{
		Use:   "address",
		Short: "Get a new wallet address",
		Long:  "Generate a new wallet address from the wallet's primary seed.",
		Run:   Wrap(walletaddresscmd),
	}

	walletAddressesCmd = &cobra.Command{
		Use:   "addresses",
		Short: "List all addresses",
		Long:  "List all addresses that have been generated by the wallet",
		Run:   Wrap(walletaddressescmd),
	}

	walletInitCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize and encrypt a new wallet",
		Long:  `Generate a new wallet from a randomly generated seed, and encrypt it.`,
		Run:   Wrap(walletinitcmd),
	}

	walletRecoverCmd = &cobra.Command{
		Use:   "recover",
		Short: "Recover and encrypt a new wallet",
		Long:  `Recover a wallet from the given mnemonic, to be used as primary seed, and encrypt it.`,
		Run:   Wrap(walletrecovercmd),
	}

	walletLoadCmd = &cobra.Command{
		Use:   "load",
		Short: "Load a wallet seed",
		// Run field is not set, as the load command itself is not a valid command.
		// A subcommand must be provided.
	}

	walletLoadSeedCmd = &cobra.Command{
		Use:   `seed`,
		Short: "Add a seed to the wallet",
		Long:  "Uses the given password to create a new wallet with that as the primary seed",
		Run:   Wrap(walletloadseedcmd),
	}

	walletLockCmd = &cobra.Command{
		Use:   "lock",
		Short: "Lock the wallet",
		Long:  "Lock the wallet, preventing further use",
		Run:   Wrap(walletlockcmd),
	}

	walletSeedsCmd = &cobra.Command{
		Use:   "seeds",
		Short: "Retrieve information about your seeds",
		Long:  "Retrieves the current seed, how many addresses are remaining, and the rest of your seeds from the wallet",
		Run:   Wrap(walletseedscmd),
	}

	walletSendCmd = &cobra.Command{
		Use:   "send",
		Short: "Send either coins or blockstakes",
		Long:  "Send either coins or blockstakes",
		// Run field is not set, as the load command itself is not a valid command.
		// A subcommand must be provided.
	}

	walletSendCoinsCmd = &cobra.Command{
		Use:   "coins <dest>|<rawCondition> <amount> [<dest>|<rawCondition> <amount>]...",
		Short: "Send coins one or multiple addresses.",
		Long: `Send coins to one or multiple addresses.
Each 'dest' must be a 78-byte hexadecimal address (Unlock Hash),
instead of an unlockHash, you can also give a JSON-encoded UnlockCondition directly,
giving you more control and options over how exactly the block stake is to be unlocked.

Amounts have to be given expressed in the OneCoin unit, and without the unit of currency.
Decimals are possible and are to be expressed using English conventions.

Amounts have to be given expressed in the OneCoin unit, and without the unit of currency.
Decimals are possible and have to be defined using the decimal point.

The Minimum Miner Fee will be added on top of the total given amount automatically.
`,
		Run: walletsendcoinscmd,
	}

	walletSendBlockStakesCmd = &cobra.Command{
		Use:   "blockstakes <dest>|<rawCondition> <amount> [<dest>|<rawCondition> <amount>]..",
		Short: "Send blockstakes to one or multiple addresses",
		Long: `Send blockstakes to one or multiple addresses.
Each 'dest' must be a 78-byte hexadecimal address (Unlock Hash),
instead of an unlockHash, you can also give a JSON-encoded UnlockCondition directly,
giving you more control and options over how exactly the block stake is to be unlocked.

Amounts have to be given expressed in the OneCoin unit, and without the unit of currency.
Decimals are possible and have to be defined using the decimal point.

The Minimum Miner Fee will be added on top of the total given amount automatically.
`,
		Run: walletsendblockstakescmd,
	}

	walletRegisterDataCmd = &cobra.Command{
		Use:   "registerdata <namespace> <data> <dest>",
		Short: "Register data on the blockchain",
		Long:  "Register data on the blockchain by sending a minimal transaction to the destination address, and including the data in the transaction",
		Run:   Wrap(walletregisterdatacmd),
	}

	walletBalanceCmd = &cobra.Command{
		Use:   "balance",
		Short: "View wallet balance",
		Long:  "View wallet balance, including confirmed and unconfirmed coins and blockstakes.",
		Run:   Wrap(walletbalancecmd),
	}

	walletTransactionsCmd = &cobra.Command{
		Use:   "transactions",
		Short: "View transactions",
		Long: `View transactions related to addresses spendable by the wallet,
providing a net flow of coins and blockstakes for each transaction.`,
		Run: Wrap(wallettransactionscmd),
	}

	walletUnlockCmd = &cobra.Command{
		Use:   `unlock`,
		Short: "Unlock the wallet",
		Long:  "Decrypt and load the wallet into memory",
		Run:   Wrap(walletunlockcmd),
	}

	walletSendTxnCmd = &cobra.Command{
		Use:   "transaction <txnjson>",
		Short: "Publish a raw transaction",
		Long:  "Publish a raw transasction. The transaction must be given in json format. The inputs don't need to be related to the current wallet",
		Run:   Wrap(walletsendtxncmd),
	}

	walletListCmd = &cobra.Command{
		Use:   "list",
		Short: "List either locked or unlocked unspent outputs",
		// Run field is not set, as the list command itself is not a valid command.
		// A subcommand must be provided.
	}

	walletListUnlockedCmd = &cobra.Command{
		Use:   "unlocked [address]",
		Args:  cobra.RangeArgs(0, 1),
		Short: "List unlocked coin and blockstake outputs",
		Long: `List all the unlocked coin and blockstake outputs that belong to this wallet.
		
If an address is given, only unspent unlocked outputs of the wallet linked to that address are shown.
`,
		Run: walletlistunlocked,
	}

	walletListLockedCmd = &cobra.Command{
		Use:   "locked [address]",
		Args:  cobra.RangeArgs(0, 1),
		Short: "List locked coin and blockstake outputs",
		Long: `List all the locked coin and blockstake outputs that belong to this wallet.

If an address is given, only unspent unlocked outputs of the wallet linked to that address are shown.
`,
		Run: walletlistlocked,
	}

	walletCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a coin or blockstake transaction",
		// Run field is not set, as the create command itself is not a valid command.
		// A subcommand must be provided.
	}

	walletCreateMultisisgAddress = &cobra.Command{
		Use:   "multisigaddress <minsigsrequired> <address1> <address2> [<address>]...",
		Short: "Create a multisig address",
		Long: `Create a multisig address from the given addresses, which requires at least <minsigrequired>
signatures to unlock`,
		Args: cobra.MinimumNArgs(3),
		Run:  walletcreatemultisigaddress,
	}

	walletCreateCoinTxnCmd = &cobra.Command{
		Use:   "cointransaction <parentID>... <dest>|<rawCondition> <amount> [<dest>|<rawCondition> <amount>]...",
		Short: "Create a new coin transaction",
		Long: `Create a new coin transaction using the given parentID's and outputs.
The outputs can be given as a pair of value and a raw output condition (or
address, which resolved to a singlesignature condition).

Amounts have to be given expressed in the OneCoin unit, and without the unit of currency.
Decimals are possible and have to be defined using the decimal point.

The Minimum Miner Fee will be added on top of the total given amount automatically.
`,
		Run: walletcreatecointxn,
	}

	walletCreateBlockStakeTxnCmd = &cobra.Command{
		Use:   "blockstaketransaction <parentID>... <dest>|<rawCondition> <amount> [<dest>|<rawCondition> <amount>]...",
		Short: "Create a new blockstake transaction",
		Long: `Create a new blockstake transaction using the given parentID's and outputs.
The outputs can be given as a pair of value and a raw output condition (or
address, which resolved to a singlesignature condition).

Amounts have to be given expressed in the OneCoin unit, and without the unit of currency.
Decimals are possible and have to be defined using the decimal point.

The Minimum Miner Fee will be added on top of the total given amount automatically.
`,
		Run: walletcreateblockstaketxn,
	}

	walletSignCmd = &cobra.Command{
		Use:   "sign <txnjson>",
		Short: "Sign inputs from the transaction",
		Long: `Signs as much of the inputs transaction. Iterate over every input, and check if they can be signed
by any of the keys in the wallet.`,
		Run: Wrap(walletsigntxn),
	}
)

var (
	walletInitCfg struct {
		NoPassphrase bool
	}

	walletRecoverCfg struct {
		NoPassphrase bool
	}
)

// walletaddresscmd fetches a new address from the wallet that will be able to
// receive coins.
func walletaddresscmd() {
	addr := new(api.WalletAddressGET)
	err := _DefaultClient.httpClient.GetAPI("/wallet/address", addr)
	if err != nil {
		DieWithError("Could not generate new address:", err)
	}
	fmt.Printf("Created new address: %s\n", addr.Address)
}

// walletaddressescmd fetches the list of addresses that the wallet knows.
func walletaddressescmd() {
	addrs := new(api.WalletAddressesGET)
	err := _DefaultClient.httpClient.GetAPI("/wallet/addresses", addrs)
	if err != nil {
		DieWithError("Failed to fetch addresses:", err)
	}
	for _, addr := range addrs.Addresses {
		fmt.Println(addr)
	}
}

// walletinitcmd encrypts the wallet with the given password
func walletinitcmd() {
	var er api.WalletInitPOST

	if !walletInitCfg.NoPassphrase {
		fmt.Println("You have to provide a passphrase!")
	}
	fmt.Println("If you have an existing mnemonic you can use the recover wallet command instead.")

	var (
		passphrase string
		err        error
	)

	if !walletInitCfg.NoPassphrase {
		passphrase, err = speakeasy.Ask("Wallet passphrase: ")
		if err != nil {
			Die("Reading passphrase failed:", err)
		}
		if passphrase == "" {
			Die("passphrase is required and cannot be empty")
		}

		repassphrase, err := speakeasy.Ask("Reenter passphrase: ")
		if err != nil {
			Die("Reading passphrase failed:", err)
		}

		if repassphrase != passphrase {
			Die("Given passphrases do not match !!")
		}
	}

	qs := fmt.Sprintf("passphrase=%s", passphrase)

	err = _DefaultClient.httpClient.PostResp("/wallet/init", qs, &er)
	if err != nil {
		DieWithError("Error when encrypting wallet:", err)
	}

	fmt.Printf("Mnemonic of primary seed:\n%s\n\n", er.PrimarySeed)
	if !walletInitCfg.NoPassphrase {
		fmt.Printf("Wallet encrypted with given passphrase\n")
	}
}

// walletrecovercmd encrypts the wallet with the given password,
// recovering a wallet for the given menmeonic to be used as primary seed.
func walletrecovercmd() {
	var er api.WalletInitPOST

	if walletInitCfg.NoPassphrase {
		fmt.Println("You have to provide an existing mnemonic!")
	} else {
		fmt.Println("You have to provide a passphrase and existing mnemonic!")
	}
	fmt.Println("If you have no existing mnemonic use the init wallet command instead!")

	var (
		passphrase string
		err        error
	)

	if !walletInitCfg.NoPassphrase {
		passphrase, err = speakeasy.Ask("Wallet passphrase: ")
		if err != nil {
			Die("Reading passphrase failed:", err)
		}
		if passphrase == "" {
			Die("passphrase is required and cannot be empty")
		}

		repassphrase, err := speakeasy.Ask("Reenter passphrase: ")
		if err != nil {
			Die("Reading passphrase failed:", err)
		}

		if repassphrase != passphrase {
			Die("Given passphrases do not match !!")
		}
	}

	mnemonic, err := speakeasy.Ask("Enter existing mnemonic to be used as primary seed: ")
	if err != nil {
		Die("Reading mnemonic failed:", err)
	}

	seed, err := modules.InitialSeedFromMnemonic(mnemonic)
	if err != nil {
		Die("Invalid mnemonic given:", err)
	}

	qs := fmt.Sprintf("passphrase=%s&seed=%s", passphrase, seed)

	err = _DefaultClient.httpClient.PostResp("/wallet/init", qs, &er)
	if err != nil {
		DieWithError("Error when encrypting wallet:", err)
	}

	if er.PrimarySeed != mnemonic {
		Die("Wallet was created, but returned primary seed mnemonic was unexpected:\n\n" + er.PrimarySeed)
	}

	fmt.Printf("Mnemonic of primary seed:\n%s\n\n", er.PrimarySeed)
	if !walletInitCfg.NoPassphrase {
		fmt.Printf("Wallet encrypted with given passphrase\n")
	}
}

// Wwlletloadseedcmd adds a seed to the wallet's list of seeds
func walletloadseedcmd() {
	passphrase, err := speakeasy.Ask("Wallet passphrase: ")
	if err != nil {
		Die("Reading passphrase failed:", err)
	}
	mnemonic, err := speakeasy.Ask("New Mnemonic: ")
	if err != nil {
		Die("Reading seed failed:", err)
	}
	qs := fmt.Sprintf("passphrase=%s&mnemonic=%s", passphrase, mnemonic)
	err = _DefaultClient.httpClient.Post("/wallet/seed", qs)
	if err != nil {
		DieWithError("Could not add seed:", err)
	}
	fmt.Println("Added Key")
}

// walletlockcmd locks the wallet
func walletlockcmd() {
	err := _DefaultClient.httpClient.Post("/wallet/lock", "")
	if err != nil {
		DieWithError("Could not lock wallet:", err)
	}
}

// walletseedscmd returns the current seed {
func walletseedscmd() {
	var seedInfo api.WalletSeedsGET
	err := _DefaultClient.httpClient.GetAPI("/wallet/seeds", &seedInfo)
	if err != nil {
		DieWithError("Error retrieving the current seed:", err)
	}
	fmt.Printf("Primary Seed: %s\n"+
		"Addresses Remaining %d\n"+
		"All Seeds:\n", seedInfo.PrimarySeed, seedInfo.AddressesRemaining)
	for _, seed := range seedInfo.AllSeeds {
		fmt.Println(seed)
	}
}

// walletsendcoinscmd sends siacoins to one or multiple destination addresses.
func walletsendcoinscmd(cmd *cobra.Command, args []string) {
	pairs, err := parsePairedOutputs(args, _CurrencyConvertor.ParseCoinString)
	if err != nil {
		cmd.UsageFunc()(cmd)
		Die(err)
	}

	body := api.WalletCoinsPOST{
		CoinOutputs: make([]types.CoinOutput, len(pairs)),
	}
	for i, pair := range pairs {
		body.CoinOutputs[i] = types.CoinOutput{
			Value:     pair.Value,
			Condition: pair.Condition,
		}
	}

	bytes, err := json.Marshal(&body)
	if err != nil {
		Die("Failed to JSON Marshal the input body:", err)
	}
	var resp api.WalletCoinsPOSTResp
	err = _DefaultClient.httpClient.PostResp("/wallet/coins", string(bytes), &resp)
	if err != nil {
		DieWithError("Could not send coins:", err)
	}
	fmt.Println("Succesfully sent coins as transaction " + resp.TransactionID.String())
	for _, co := range body.CoinOutputs {
		fmt.Printf("Sent %s to %s (using ConditionType %d)\n",
			_CurrencyConvertor.ToCoinStringWithUnit(co.Value), co.Condition.UnlockHash(),
			co.Condition.ConditionType())
	}
}

// walletsendblockstakescmd sends block stakes to one or multiple destination addresses.
func walletsendblockstakescmd(cmd *cobra.Command, args []string) {
	pairs, err := parsePairedOutputs(args, stringToBlockStakes)
	if err != nil {
		cmd.UsageFunc()(cmd)
		Die(err)
	}

	body := api.WalletBlockStakesPOST{
		BlockStakeOutputs: make([]types.BlockStakeOutput, len(pairs)),
	}
	for i, pair := range pairs {
		body.BlockStakeOutputs[i] = types.BlockStakeOutput{
			Value:     pair.Value,
			Condition: pair.Condition,
		}
	}

	bytes, err := json.Marshal(&body)
	if err != nil {
		Die("Failed to JSON Marshal the input body:", err)
	}
	var resp api.WalletBlockStakesPOSTResp
	err = _DefaultClient.httpClient.PostResp("/wallet/blockstakes", string(bytes), &resp)
	if err != nil {
		DieWithError("Could not send block stakes:", err)
	}
	fmt.Println("Succesfully sent blockstakes as transaction " + resp.TransactionID.String())
	for _, bo := range body.BlockStakeOutputs {
		fmt.Printf("Sent %s BS to %s (using ConditionType %d)\n",
			bo.Value, bo.Condition.UnlockHash(), bo.Condition.ConditionType())
	}
}

type outputPair struct {
	Condition types.UnlockConditionProxy
	Value     types.Currency
}

// parseCurrencyString takes the string representation of a currency value
type parseCurrencyString func(string) (types.Currency, error)

func stringToBlockStakes(input string) (types.Currency, error) {
	bsv, err := strconv.ParseUint(input, 10, 64)
	return types.NewCurrency64(bsv), err
}

func parsePairedOutputs(args []string, parseCurrency parseCurrencyString) (pairs []outputPair, err error) {
	argn := len(args)
	if argn < 2 {
		err = errors.New("not enough arguments, at least 2 required")
		return
	}
	if argn%2 != 0 {
		err = errors.New("arguments have to be given in pairs of '<dest>|<rawCondition>'+'<value>'")
		return
	}

	for i := 0; i < argn; i += 2 {
		// parse value first, as it's the one without any possibility of ambiguity
		var pair outputPair
		pair.Value, err = parseCurrency(args[i+1])
		if err != nil {
			err = fmt.Errorf("failed to parse amount/value for output #%d: %v", i/2, err)
			return
		}

		// try to parse it as an unlock hash
		var uh types.UnlockHash
		err = uh.LoadString(args[i])
		if err == nil {
			// parsing as an unlock hash was succesfull, store the pair and continue to the next pair
			pair.Condition = types.NewCondition(types.NewUnlockHashCondition(uh))
			pairs = append(pairs, pair)
			continue
		}

		// try to parse it as a JSON-encoded unlock condition
		err = pair.Condition.UnmarshalJSON([]byte(args[i]))
		if err != nil {
			err = fmt.Errorf("condition has to be UnlockHash or JSON-encoded UnlockCondition, output #%d's was neither", i/2)
			return
		}
		pairs = append(pairs, pair)
	}
	return
}

// walletregisterdatacmd registers data on the blockchain by making a minimal transaction to the designated address
// and includes the data in the transaction
func walletregisterdatacmd(namespace, dest, data string) {
	encodedData := base64.StdEncoding.EncodeToString([]byte(namespace + data))
	err := _DefaultClient.httpClient.Post("/wallet/data",
		fmt.Sprintf("destination=%s&data=%s", dest, encodedData))
	if err != nil {
		DieWithError("Could not register data:", err)
	}
	fmt.Printf("Registered data to %s\n", dest)
}

// walletblockstakestatcmd gives all statistical info of blockstake
func walletblockstakestatcmd() {
	bsstat := new(api.WalletBlockStakeStatsGET)
	err := _DefaultClient.httpClient.GetAPI("/wallet/blockstakestats", bsstat)
	if err != nil {
		DieWithError("Could not gen blockstake info:", err)
	}
	fmt.Printf("BlockStake stats:\n")
	fmt.Printf("Total active Blockstake is %v\n", bsstat.TotalActiveBlockStake)
	fmt.Printf("This account has %v Blockstake\n", bsstat.TotalBlockStake)
	fmt.Printf("%v of last %v Blocks created (theoretically %v)\n", bsstat.TotalBCLast1000, bsstat.BlockCount, bsstat.TotalBCLast1000t)

	fmt.Printf("containing %v fee \n",
		_CurrencyConvertor.ToCoinStringWithUnit(bsstat.TotalFeeLast1000))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight|tabwriter.Debug)
	fmt.Fprintln(w, "state\t#BlockStake\tUTXO hash\t")

	for i, BSstate := range bsstat.BlockStakeState {
		state := "active"
		if BSstate == 0 {
			state = "not active"
		}
		fmt.Fprintf(w, "%v\t%v\t%v\t\n", state, bsstat.BlockStakeNumOf[i], bsstat.BlockStakeUTXOAddress[i])
	}
	w.Flush()
}

// walletbalancecmd retrieves and displays information about the wallet.
func walletbalancecmd() {
	status := new(api.WalletGET)
	err := _DefaultClient.httpClient.GetAPI("/wallet", status)
	if err != nil {
		DieWithError("Could not get wallet status:", err)
	}
	encStatus := "Unencrypted"
	if status.Encrypted {
		encStatus = "Encrypted"
	}
	if !status.Unlocked {
		DieWithExitCode(ExitCodeUsage, fmt.Sprintf(`Wallet status:
%v, Locked
Unlock the wallet to view balance
`, encStatus))
	}

	unconfirmedBalance := status.ConfirmedCoinBalance.Add(status.UnconfirmedIncomingCoins).Sub(status.UnconfirmedOutgoingCoins)
	var delta string
	if unconfirmedBalance.Cmp(status.ConfirmedCoinBalance) >= 0 {
		delta = "+ " + _CurrencyConvertor.ToCoinStringWithUnit(unconfirmedBalance.Sub(status.ConfirmedCoinBalance))
	} else {
		delta = "- " + _CurrencyConvertor.ToCoinStringWithUnit(status.ConfirmedCoinBalance.Sub(unconfirmedBalance))
	}

	fmt.Printf(`Wallet status:
%s, Unlocked
Confirmed Balance:   %v
Locked Balance:      %v
Unconfirmed Delta:   %v
BlockStakes:         %v BS
`, encStatus, _CurrencyConvertor.ToCoinStringWithUnit(status.ConfirmedCoinBalance),
		_CurrencyConvertor.ToCoinStringWithUnit(status.ConfirmedLockedCoinBalance),
		delta, status.BlockStakeBalance)
	if !status.LockedBlockStakeBalance.IsZero() {
		fmt.Printf("Locked BlockStakes:  %v BS\n", status.LockedBlockStakeBalance)
	}

	if len(status.MultiSigWallets) > 0 {
		fmt.Println()
		fmt.Println("Multisig Wallets:")
	}

	for _, wallet := range status.MultiSigWallets {
		// Print separator
		fmt.Println()
		fmt.Println("==============================================================================")
		fmt.Println()

		unconfirmedBalance := wallet.ConfirmedCoinBalance.Add(wallet.UnconfirmedIncomingCoins).Sub(wallet.UnconfirmedOutgoingCoins)
		var coindelta string
		if unconfirmedBalance.Cmp(wallet.ConfirmedCoinBalance) >= 0 {
			coindelta = "+ " + _CurrencyConvertor.ToCoinStringWithUnit(unconfirmedBalance.Sub(wallet.ConfirmedCoinBalance))
		} else {
			coindelta = "- " + _CurrencyConvertor.ToCoinStringWithUnit(wallet.ConfirmedCoinBalance.Sub(unconfirmedBalance))
		}

		unconfirmedBlockStakeBalance := wallet.ConfirmedBlockStakeBalance.Add(wallet.UnconfirmedIncomingBlockStakes).Sub(wallet.UnconfirmedOutgoingBlockStakes)
		var bsdelta string
		if unconfirmedBlockStakeBalance.Cmp(wallet.ConfirmedBlockStakeBalance) >= 0 {
			bsdelta = "+ " + unconfirmedBalance.Sub(wallet.ConfirmedBlockStakeBalance).String()
		} else {
			bsdelta = "- " + wallet.ConfirmedBlockStakeBalance.Sub(unconfirmedBlockStakeBalance).String()
		}

		fmt.Printf("%v\n", wallet.Address)
		fmt.Printf("Confirmed Balance:            %v\n", _CurrencyConvertor.ToCoinStringWithUnit(wallet.ConfirmedCoinBalance))
		if !wallet.ConfirmedLockedCoinBalance.IsZero() {
			fmt.Printf("Locked Balance:               %v\n", _CurrencyConvertor.ToCoinStringWithUnit(wallet.ConfirmedLockedCoinBalance))
		}
		if wallet.UnconfirmedIncomingCoins.Cmp(wallet.UnconfirmedOutgoingCoins) != 0 {
			fmt.Printf("Unconfirmed Delta:            %v\n", coindelta)
		}
		if !wallet.ConfirmedBlockStakeBalance.IsZero() {
			fmt.Printf("BlockStakes:                  %v BS\n", wallet.ConfirmedBlockStakeBalance)
		}
		if !wallet.ConfirmedLockedBlockStakeBalance.IsZero() {
			fmt.Printf("Locked BlockStakes:           %v BS\n", wallet.ConfirmedLockedBlockStakeBalance)
		}
		if wallet.UnconfirmedIncomingBlockStakes.Cmp(wallet.UnconfirmedOutgoingBlockStakes) != 0 {
			fmt.Printf("Unconfirmed blockstake delta: %v BS\n", bsdelta)
		}

		fmt.Println()
		fmt.Println("Possible signatories:")
		for _, uh := range wallet.Owners {
			fmt.Println(uh)
		}
		fmt.Println()
		fmt.Println("Minimum signatures required:", wallet.MinSigs)
	}
}

// wallettransactionscmd lists all of the transactions related to the wallet,
// providing a net flow of siacoins and siafunds for each.
func wallettransactionscmd() {
	wtg := new(api.WalletTransactionsGET)
	err := _DefaultClient.httpClient.GetAPI("/wallet/transactions?startheight=0&endheight=10000000", wtg)
	if err != nil {
		DieWithError("Could not fetch transaction history:", err)
	}

	multiSigWalletTxns := make(map[types.UnlockHash][]modules.ProcessedTransaction)
	txns := append(wtg.ConfirmedTransactions, wtg.UnconfirmedTransactions...)

	if len(txns) == 0 {
		fmt.Println("This wallet has no transaction related to it.")
		return
	}

	// get config from the in-memory storage
	cfg := _ConfigStorage.Config()

	fmt.Println("    [height]                                                   [transaction id]       [net coins]   [net blockstakes]")
	for _, txn := range txns {
		var relatedMultiSigUnlockHashes []types.UnlockHash
		// Determine the number of outgoing siacoins and siafunds.
		var outgoingSiacoins types.Currency
		var outgoingBlockStakes types.Currency
		var rootWalletOwned bool
		for _, input := range txn.Inputs {
			if input.FundType == types.SpecifierCoinInput && input.WalletAddress {
				rootWalletOwned = true
				outgoingSiacoins = outgoingSiacoins.Add(input.Value)
			}
			if input.FundType == types.SpecifierBlockStakeInput && input.WalletAddress {
				rootWalletOwned = true
				outgoingBlockStakes = outgoingBlockStakes.Add(input.Value)
			}
			if input.RelatedAddress.Type == types.UnlockTypeMultiSig {
				relatedMultiSigUnlockHashes = append(relatedMultiSigUnlockHashes, input.RelatedAddress)
			}
		}

		// Determine the number of incoming siacoins and siafunds.
		var incomingSiacoins types.Currency
		var incomingBlockStakes types.Currency
		for _, output := range txn.Outputs {
			if output.FundType == types.SpecifierMinerPayout {
				rootWalletOwned = true
				incomingSiacoins = incomingSiacoins.Add(output.Value)
			}
			if output.FundType == types.SpecifierCoinOutput && output.WalletAddress {
				rootWalletOwned = true
				incomingSiacoins = incomingSiacoins.Add(output.Value)
			}
			if output.FundType == types.SpecifierBlockStakeOutput && output.WalletAddress {
				rootWalletOwned = true
				incomingBlockStakes = incomingBlockStakes.Add(output.Value)
			}
			if output.RelatedAddress.Type == types.UnlockTypeMultiSig {
				relatedMultiSigUnlockHashes = append(relatedMultiSigUnlockHashes, output.RelatedAddress)
			}
		}

		// Remember the txn to print it in case there are related special conditions
		for _, uh := range relatedMultiSigUnlockHashes {
			multiSigWalletTxns[uh] = append(multiSigWalletTxns[uh], txn)
		}
		// Only print here if there is a direct relation to the root wallet
		if !rootWalletOwned {
			continue
		}

		// Convert the siacoins to a float.
		incomingSiacoinsFloat, _ := new(big.Rat).SetFrac(incomingSiacoins.Big(), cfg.CurrencyUnits.OneCoin.Big()).Float64()
		outgoingSiacoinsFloat, _ := new(big.Rat).SetFrac(outgoingSiacoins.Big(), cfg.CurrencyUnits.OneCoin.Big()).Float64()

		// Print the results.
		if txn.ConfirmationHeight < 1e9 {
			fmt.Printf("%12v", txn.ConfirmationHeight-1)
		} else {
			fmt.Printf(" unconfirmed")
		}
		fmt.Printf("%67v%15.2f %s", txn.TransactionID, incomingSiacoinsFloat-outgoingSiacoinsFloat, cfg.CurrencyCoinUnit)
		incomingBlockStakeBigInt := incomingBlockStakes.Big()
		outgoingBlockStakeBigInt := outgoingBlockStakes.Big()
		fmt.Printf("%14s BS\n", new(big.Int).Sub(incomingBlockStakeBigInt, outgoingBlockStakeBigInt).String())

	}

	if len(multiSigWalletTxns) > 0 {

		for uh, txns := range multiSigWalletTxns {
			for _, txn := range txns {
				fmt.Println()
				fmt.Println("=====================================================================================================================")
				fmt.Println()

				fmt.Println("Wallet Address:", uh)
				fmt.Println()
				fmt.Println("    [height]                                             [transaction/block id]       [net coins]   [net blockstakes]")

				// Determine the number of outgoing siacoins and siafunds.
				var outgoingSiacoins types.Currency
				var outgoingBlockStakes types.Currency
				for _, input := range txn.Inputs {
					if input.FundType == types.SpecifierCoinInput && input.RelatedAddress.Cmp(uh) == 0 {
						outgoingSiacoins = outgoingSiacoins.Add(input.Value)
					}
					if input.FundType == types.SpecifierBlockStakeInput && input.RelatedAddress.Cmp(uh) == 0 {
						outgoingBlockStakes = outgoingBlockStakes.Add(input.Value)
					}
				}

				// Determine the number of incoming siacoins and siafunds.
				var incomingSiacoins types.Currency
				var incomingBlockStakes types.Currency
				for _, output := range txn.Outputs {
					if output.FundType == types.SpecifierMinerPayout {
						incomingSiacoins = incomingSiacoins.Add(output.Value)
					}
					if output.FundType == types.SpecifierCoinOutput && output.RelatedAddress.Cmp(uh) == 0 {
						incomingSiacoins = incomingSiacoins.Add(output.Value)
					}
					if output.FundType == types.SpecifierBlockStakeOutput && output.RelatedAddress.Cmp(uh) == 0 {
						incomingBlockStakes = incomingBlockStakes.Add(output.Value)
					}
				}

				// Convert the siacoins to a float.
				incomingSiacoinsFloat, _ := new(big.Rat).SetFrac(incomingSiacoins.Big(), cfg.CurrencyUnits.OneCoin.Big()).Float64()
				outgoingSiacoinsFloat, _ := new(big.Rat).SetFrac(outgoingSiacoins.Big(), cfg.CurrencyUnits.OneCoin.Big()).Float64()

				// Print the results.
				if txn.ConfirmationHeight < 1e9 {
					fmt.Printf("%12v", txn.ConfirmationHeight-1)
				} else {
					fmt.Printf(" unconfirmed")
				}
				fmt.Printf("%67v%15.2f %s", txn.TransactionID, incomingSiacoinsFloat-outgoingSiacoinsFloat, cfg.CurrencyCoinUnit)
				incomingBlockStakeBigInt := incomingBlockStakes.Big()
				outgoingBlockStakeBigInt := outgoingBlockStakes.Big()
				fmt.Printf("%14s BS\n", new(big.Int).Sub(incomingBlockStakeBigInt, outgoingBlockStakeBigInt).String())
			}
		}
	}
}

// walletunlockcmd unlocks a saved wallet
func walletunlockcmd() {
	password, err := speakeasy.Ask("Wallet password: ")
	if err != nil {
		Die("Reading password failed:", err)
	}
	fmt.Println("Unlocking the wallet. This may take several minutes...")
	qs := fmt.Sprintf("passphrase=%s", password)
	err = _DefaultClient.httpClient.Post("/wallet/unlock", qs)
	if err != nil {
		DieWithError("Could not unlock wallet:", err)
	}
	fmt.Println("Wallet unlocked")
}

// walletsendtxncmd sends commits a transaction in json format
// to the transaction pool
func walletsendtxncmd(txnjson string) {
	var resp api.TransactionPoolPOST
	err := _DefaultClient.httpClient.PostResp("/transactionpool/transactions", txnjson, &resp)
	if err != nil {
		DieWithError("Could not publish transaction:", err)
	}
	fmt.Println("Transaction published, transaction id:", resp.TransactionID)
}

func walletlistunlocked(_ *cobra.Command, args []string) {
	var (
		err          error
		address      types.UnlockHash
		addressGiven = len(args) == 1
	)
	if addressGiven {
		err = address.LoadString(args[0])
		if err != nil {
			Die("failed to parse given wallet address: ", err)
		}
	}

	var resp api.WalletListUnlockedGET
	err = _DefaultClient.httpClient.GetAPI("/wallet/unlocked", &resp)
	if err != nil {
		DieWithError("failed to get unlocked outputs: ", err)
	}

	if addressGiven {
		// filter out all outputs we do not care about
		for idx := 0; idx < len(resp.UnlockedCoinOutputs); {
			if resp.UnlockedCoinOutputs[idx].Output.Condition.UnlockHash().Cmp(address) == 0 {
				idx++
				continue
			}
			resp.UnlockedCoinOutputs = append(
				resp.UnlockedCoinOutputs[:idx],
				resp.UnlockedCoinOutputs[idx+1:]...)
		}
		for idx := 0; idx < len(resp.UnlockedBlockstakeOutputs); {
			if resp.UnlockedBlockstakeOutputs[idx].Output.Condition.UnlockHash().Cmp(address) == 0 {
				idx++
				continue
			}
			resp.UnlockedBlockstakeOutputs = append(
				resp.UnlockedBlockstakeOutputs[:idx],
				resp.UnlockedBlockstakeOutputs[idx+1:]...)
		}
	}

	if len(resp.UnlockedBlockstakeOutputs) == 0 && len(resp.UnlockedCoinOutputs) == 0 {
		if addressGiven {
			fmt.Println("No unlocked outputs matched to address: " + address.String())
		} else {
			fmt.Println("No unlocked outputs")
		}
		return
	}

	jsonOutput := json.NewEncoder(os.Stdout)

	if len(resp.UnlockedCoinOutputs) > 0 {
		fmt.Println("Unlocked unspent coin outputs:")
		for _, uco := range resp.UnlockedCoinOutputs {
			fmt.Println("ID:", uco.ID)
			fmt.Println("Value:", _CurrencyConvertor.ToCoinStringWithUnit(uco.Output.Value))
			fmt.Println("Condition:")
			jsonOutput.Encode(uco.Output)
			fmt.Println()
		}
	}

	if len(resp.UnlockedBlockstakeOutputs) > 0 {
		fmt.Println("Unlocked unspent blockstake outputs:")
		for _, ubso := range resp.UnlockedBlockstakeOutputs {
			fmt.Println("ID:", ubso.ID)
			fmt.Println("Value:", ubso.Output.Value, "BS")
			fmt.Println("Condition:")
			jsonOutput.Encode(ubso.Output)
			fmt.Println()
		}
	}
}

func walletlistlocked(_ *cobra.Command, args []string) {
	var (
		err          error
		address      types.UnlockHash
		addressGiven = len(args) == 1
	)
	if addressGiven {
		err = address.LoadString(args[0])
		if err != nil {
			Die("failed to parse given wallet address: ", err)
		}
	}

	var resp api.WalletListLockedGET
	err = _DefaultClient.httpClient.GetAPI("/wallet/locked", &resp)
	if err != nil {
		DieWithError("Could not get locked outputs: ", err)
	}

	if addressGiven {
		// filter out all outputs we do not care about
		for idx := 0; idx < len(resp.LockedCoinOutputs); {
			if resp.LockedCoinOutputs[idx].Output.Condition.UnlockHash().Cmp(address) == 0 {
				idx++
				continue
			}
			resp.LockedCoinOutputs = append(
				resp.LockedCoinOutputs[:idx],
				resp.LockedCoinOutputs[idx+1:]...)
		}
		for idx := 0; idx < len(resp.LockedBlockstakeOutputs); {
			if resp.LockedBlockstakeOutputs[idx].Output.Condition.UnlockHash().Cmp(address) == 0 {
				idx++
				continue
			}
			resp.LockedBlockstakeOutputs = append(
				resp.LockedBlockstakeOutputs[:idx],
				resp.LockedBlockstakeOutputs[idx+1:]...)
		}
	}

	if len(resp.LockedBlockstakeOutputs) == 0 && len(resp.LockedCoinOutputs) == 0 {
		if addressGiven {
			fmt.Println("No locked outputs matched to address: " + address.String())
		} else {
			fmt.Println("No locked outputs")
		}
		return
	}

	jsonOutput := json.NewEncoder(os.Stdout)

	if len(resp.LockedCoinOutputs) > 0 {
		fmt.Println("Locked unspent coin outputs:")
		for _, uco := range resp.LockedCoinOutputs {
			fmt.Println("ID:", uco.ID)
			fmt.Println("Value:", _CurrencyConvertor.ToCoinStringWithUnit(uco.Output.Value))
			fmt.Println("Condition:")
			jsonOutput.Encode(uco.Output)
			fmt.Println()
		}
	}

	if len(resp.LockedBlockstakeOutputs) > 0 {
		fmt.Println("Locked unspent blockstake outputs:")
		for _, ubso := range resp.LockedBlockstakeOutputs {
			fmt.Println("ID:", ubso.ID)
			fmt.Println("Value:", ubso.Output.Value, "BS")
			fmt.Println("Condition:")
			jsonOutput.Encode(ubso.Output)
			fmt.Println()
		}
	}
}

func walletcreatemultisigaddress(cmd *cobra.Command, args []string) {
	msr, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		Die(err)
	}

	if uint64(len(args[1:])) < msr {
		Die("Invalid amount of signatures required")
	}

	uhs := types.UnlockHashSlice{}
	var uh types.UnlockHash
	for _, addr := range args[1:] {
		err = uh.LoadString(addr)
		if err != nil {
			Die("Failed to load unlock hash:", err)
		}
		uhs = append(uhs, uh)
	}

	multiSigCond := types.NewMultiSignatureCondition(uhs, msr)
	fmt.Println("Multisig address:", multiSigCond.UnlockHash())
}

func walletcreatecointxn(cmd *cobra.Command, args []string) {
	// parse first arguments as coin inputs
	inputs := []types.CoinOutputID{}
	var id types.CoinOutputID
	for _, possibleInputID := range args {
		if err := id.LoadString(possibleInputID); err != nil {
			break
		}
		inputs = append(inputs, id)
	}

	// Check that the remaining args are condition + value pairs
	if (len(args)-len(inputs))%2 != 0 {
		cmd.UsageFunc()(cmd)
		Die("Invalid arguments. Arguments must be of the form <parentID>... <dest>|<rawCondition> <amount> [<dest>|<rawCondition> <amount>]...")
	}

	// parse the remainder as output coditions and values
	pairs, err := parsePairedOutputs(args[len(inputs):], _CurrencyConvertor.ParseCoinString)
	if err != nil {
		cmd.UsageFunc()(cmd)
		Die(err)
	}

	body := api.WalletCreateTransactionPOST{}
	body.CoinInputs = inputs
	for _, pair := range pairs {
		body.CoinOutputs = append(body.CoinOutputs, types.CoinOutput{Value: pair.Value, Condition: pair.Condition})
	}

	buffer := bytes.NewBuffer(nil)
	err = json.NewEncoder(buffer).Encode(body)
	if err != nil {
		Die("Could not create raw transaction from inputs and outputs: ", err)
	}
	var resp api.WalletCreateTransactionRESP
	err = _DefaultClient.httpClient.PostResp("/wallet/create/transaction", buffer.String(), &resp)
	if err != nil {
		DieWithError("Failed to create transaction:", err)
	}

	json.NewEncoder(os.Stdout).Encode(resp.Transaction)
}

func walletcreateblockstaketxn(cmd *cobra.Command, args []string) {
	// parse first arguments as coin inputs
	inputs := []types.BlockStakeOutputID{}
	var id types.BlockStakeOutputID
	for _, possibleInputID := range args {
		if err := id.LoadString(possibleInputID); err != nil {
			break
		}
		inputs = append(inputs, id)
	}

	// Check that the remaining args are condition + value pairs
	if (len(args)-len(inputs))%2 != 0 {
		cmd.UsageFunc()(cmd)
		Die("Invalid arguments. Arguments must be of the form <parentID>... <dest>|<rawCondition> <amount> [<dest>|<rawCondition> <amount>]...")
	}

	// parse the remainder as output coditions and values
	pairs, err := parsePairedOutputs(args[len(inputs):], stringToBlockStakes)
	if err != nil {
		cmd.UsageFunc()(cmd)
		Die(err)
	}

	body := api.WalletCreateTransactionPOST{}
	body.BlockStakeInputs = inputs
	for _, pair := range pairs {
		body.BlockStakeOutputs = append(body.BlockStakeOutputs, types.BlockStakeOutput{Value: pair.Value, Condition: pair.Condition})
	}

	buffer := bytes.NewBuffer(nil)
	err = json.NewEncoder(buffer).Encode(body)
	if err != nil {
		Die("Could not create raw transaction from inputs and outputs: ", err)
	}
	var resp api.WalletCreateTransactionRESP
	err = _DefaultClient.httpClient.PostResp("/wallet/create/transaction", buffer.String(), &resp)
	if err != nil {
		DieWithError("Failed to create transaction:", err)
	}

	json.NewEncoder(os.Stdout).Encode(resp.Transaction)
}

func walletsigntxn(txnjson string) {
	var txn types.Transaction
	err := _DefaultClient.httpClient.PostResp("/wallet/sign", txnjson, &txn)
	if err != nil {
		DieWithError("Failed to sign transaction:", err)
	}

	json.NewEncoder(os.Stdout).Encode(txn)
}

func init() {
	walletInitCmd.Flags().BoolVar(
		&walletInitCfg.NoPassphrase, "no-passphrase", false,
		"create an unencrypted (less secure) wallet")

	walletRecoverCmd.Flags().BoolVar(
		&walletRecoverCfg.NoPassphrase, "no-passphrase", false,
		"recover seed into a new and unencrypted (less secure) wallet")
}
