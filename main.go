package main

import (
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"sync"

	hbls "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/tyler-smith/go-bip39"
	util "github.com/wealdtech/go-eth2-util"
)

func init() {
	hbls.Init(hbls.BLS12_381)
	hbls.SetETHmode(hbls.EthModeLatest)
}

func main() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		log.Printf("Failed to read build info")
		return
	}

	blsVersion := ""
	for _, dep := range bi.Deps {
		if dep.Path == "github.com/herumi/bls-eth-go-binary" {
			blsVersion = dep.Version
			break
		}
	}

	fmt.Printf("BLS version: %v\n", blsVersion)
	fmt.Printf("BLS test: ")

	var errs []error
	errsMtx := sync.Mutex{}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := testBlsMath()

			if len(err) > 0 {
				errsMtx.Lock()
				errs = append(errs, err...)
				errsMtx.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(errs) > 0 {
		fmt.Printf("failed\n")

		for _, err := range errs {
			fmt.Printf("  %v\n", err)
		}
	} else {
		fmt.Printf("passed\n")
	}
}

// testBlsMath tests the BLS math
// this seems broken for some CPU types
func testBlsMath() (errs []error) {
	errs = []error{}
	mnemonic := "trigger mouse legal obey solve noble light employ shrug length kiwi make neutral friend divide like fortune outside trim install ocean gap token honey"
	pubkeys := []string{
		"0xb3c59dd04900cdcd10be94e31a9bf302ad9a323a1bb3fb710c44e7f5b7acd4ce35a590de88a640dce9b8dff3fc188a39",
		"0xa2caa2dc8b2295fe6ff78815cbe42a5103c668fb3a4e796a56d40145a192a2ce7e2be0d38cda931b6373e5c96d0f8a50",
		"0x8bfcfd33fda4385788b9c028f8025c35488b5187dfcd3901ac498a3ef0a6dbd0076e4d1f7b028c863e7e684713ff2521",
		"0x89e5207d07509abe027003c9adcc88649d072620e2583b212b2c1284d0a14aaf072b72e463997b39ca60bddeffa04896",
		"0x89d6cf68072d6a93aab7b4101d2c38cb514c2971460dd1430ae4a900969491b9927b5368d0c967bc0dc23b25798cde4c",
		"0x9861ce59afa1623bccee64b0caa6a195bb48ff60c932a0b355cc08f3ee6c3ab2a2dda4d7da04fe8c6ff07cfcf06c3081",
		"0xa9d49d74114bba6059528831ff053a9024e11f98a3eb3c5c73607ad78d7ca2d7379424a9ff0cc020523fdfed6cb3e6c3",
		"0x8f47915127f9b9692812f8bcd9b630b8766c9baac92540f222745fb2112e4c4ad5d72fd5462f5724a0faa550ba795f23",
		"0x97e8fafd9233f72a3da52805311bece0f405b64e80d0c831b5c8a2bb978b0a026f460e66789338a3e8057db6f5eece68",
		"0x8f0eb2ed68556fd0ee84c0b1fcf107617f88f4a9a390963b3b8a242a64ffcf481cd9424e74e6d2bb05caf40d3c16774f",
	}

	mnemonic = strings.TrimSpace(mnemonic)
	if !bip39.IsMnemonicValid(mnemonic) {
		errs = append(errs, errors.New("mnemonic is not valid"))
		return
	}

	seed := bip39.NewSeed(mnemonic, "")

	for accountIdx := 0; accountIdx < 10; accountIdx++ {
		validatorKeyPath := fmt.Sprintf("m/12381/3600/%d/0/0", accountIdx)

		validatorPrivkey, err := util.PrivateKeyFromSeedAndPath(seed, validatorKeyPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed generating validator key %v (%v): %w", accountIdx, validatorKeyPath, err))
			continue
		}

		validatorPubkey := validatorPrivkey.PublicKey().Marshal()
		validatorPubkeyStr := fmt.Sprintf("0x%x", validatorPubkey)

		if validatorPubkeyStr != pubkeys[accountIdx] {
			errs = append(errs, fmt.Errorf("validator pubkey %v mismatch: %v != %v", accountIdx, validatorPubkeyStr, pubkeys[accountIdx]))
		}
	}

	return
}
