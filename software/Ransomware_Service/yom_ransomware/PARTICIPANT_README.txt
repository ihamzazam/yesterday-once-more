WannaCry Incident Lab: Participant Instructions

The documents folder on this machine has been attacked. Each document was
replaced by a ransomware envelope named <original-name>.WNCRY (for example
notes.txt.WNCRY), and the plaintext original is gone. The ransom note in the
same folder says so too. This instruction file is available before and after
the incident; its presence alone does not mean the host has been affected.

Open the participant menu on this machine:

    ransom

From the home screen:

  [2] Inspect documents shows the current state of every document. ORIGINAL
      means the plaintext contents match the recorded original. LOCKED
      (.WNCRY) means the ransomware envelope is present.

  [6] My wallet creates and checks your lab wallet. c creates a
      password-protected wallet, r refreshes its balance, l looks up a pasted
      address, and b returns home.

  [3] SEED Exchange is where you buy lab ETH to pay the ransom. Choose a
      preset amount or a custom amount (1-5 lab ETH); the order is settled on
      the lab's private chain.

  [5] Document recovery runs the enforced exchange: it registers your request
      on-chain with the exact ransom payment (the RansomExchange contract
      rejects any other amount), waits for the attacker's reply, unseals your
      file key with your recovered private key, and prints the KEY GRANTED
      screen. Copy that key, leave the menu, and run the decryptor:

          ransom decrypt

      Paste the key when asked. The decryptor decrypts every document,
      verifies each against its original, restores the original filenames,
      and removes the .WNCRY envelopes. Report any error rather than assuming
      success.

The encrypted envelope of your private key was sent to the attacker through
the blockchain. It is useless to anyone without the attacker's private key,
which never exists on this host. After payment the attacker replied on-chain
in plaintext (they do not care about your privacy); only that reply lets you
unseal your own file key.

Use b to return from a screen and 0 at home to exit. Only one participant
menu can be active per host at a time. Run one action at a time.

For a one-screen summary at any time, run:  ransom status
