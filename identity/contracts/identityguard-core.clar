;; IdentityGuard Core - Streamlined Identity Management
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u100))
(define-constant ERR_IDENTITY_NOT_FOUND (err u101))
(define-constant ERR_ALREADY_VERIFIED (err u102))
(define-constant ERR_INVALID_VERIFIER (err u103))
(define-constant ERR_INVALID_CLAIM (err u105))
(define-constant ERR_INVALID_INPUT (err u106))
(define-constant ERR_CONTRACT_PAUSED (err u108))
(define-data-var next-identity-id uint u1)
(define-data-var verification-fee uint u500000)
(define-data-var contract-paused bool false)
(define-map identities
  { identity-id: uint }
  {
    owner: principal,
    did: (string-ascii 100),
    created-at: uint,
    is-active: bool
  }
)

(define-map identity-claims
  { identity-id: uint, claim-type: (string-ascii 50) }
  {
    claim-value-hash: (string-ascii 64),
    verifier: (optional principal),
    is-verified: bool,
    is-public: bool
  }
)

(define-map authorized-verifiers
  { verifier: principal }
  { is-active: bool }
)

(define-map user-identities
  { user: principal }
  { identity-id: (optional uint) }
)

(define-private (is-contract-paused) (var-get contract-paused))
(define-private (is-authorized-verifier (verifier principal))
  (default-to false (get is-active (map-get? authorized-verifiers { verifier: verifier }))))
(define-private (validate-string-input (input (string-ascii 100)))
  (and (> (len input) u0) (<= (len input) u100)))
(define-private (validate-claim-type (claim-type (string-ascii 50)))
  (and (> (len claim-type) u0) (<= (len claim-type) u50)))
(define-private (validate-hash (hash (string-ascii 64))) (is-eq (len hash) u64))

;; Register new identity
(define-public (register-identity (did (string-ascii 100)))
  (let ((identity-id (var-get next-identity-id)))
    (asserts! (not (is-contract-paused)) ERR_CONTRACT_PAUSED)
    (asserts! (validate-string-input did) ERR_INVALID_INPUT)
    (asserts! (is-none (get identity-id (map-get? user-identities { user: tx-sender }))) ERR_ALREADY_VERIFIED)
    
    ;; Store identity
    (map-set identities
      { identity-id: identity-id }
      {
        owner: tx-sender,
        did: did,
        created-at: stacks-block-height,
        is-active: true
      }
    )
    
    ;; Link user to identity
    (map-set user-identities
      { user: tx-sender }
      { identity-id: (some identity-id) }
    )
    
    ;; Increment identity ID
    (var-set next-identity-id (+ identity-id u1))
    
    (ok identity-id)
  )
)

;; Add identity claim
(define-public (add-claim
  (claim-type (string-ascii 50))
  (claim-value-hash (string-ascii 64))
  (is-public bool)
)
  (let ((user-identity (unwrap! (unwrap! (get identity-id (map-get? user-identities { user: tx-sender })) ERR_IDENTITY_NOT_FOUND) ERR_IDENTITY_NOT_FOUND)))
    (asserts! (not (is-contract-paused)) ERR_CONTRACT_PAUSED)
    (asserts! (validate-claim-type claim-type) ERR_INVALID_INPUT)
    (asserts! (validate-hash claim-value-hash) ERR_INVALID_INPUT)
    
    ;; Store claim
    (map-set identity-claims
      { identity-id: user-identity, claim-type: claim-type }
      {
        claim-value-hash: claim-value-hash,
        verifier: none,
        is-verified: false,
        is-public: is-public
      }
    )
    
    (ok true)
  )
)

;; Verify claim (verifier only)
(define-public (verify-claim 
  (identity-id uint)
  (claim-type (string-ascii 50))
)
  (let ((claim-data (unwrap! (map-get? identity-claims { identity-id: identity-id, claim-type: claim-type }) ERR_INVALID_CLAIM)))
    (asserts! (not (is-contract-paused)) ERR_CONTRACT_PAUSED)
    (asserts! (validate-claim-type claim-type) ERR_INVALID_INPUT)
    (asserts! (> identity-id u0) ERR_INVALID_INPUT)
    (asserts! (is-authorized-verifier tx-sender) ERR_INVALID_VERIFIER)
    (asserts! (not (get is-verified claim-data)) ERR_ALREADY_VERIFIED)
    
    ;; Pay verification fee
    (try! (stx-transfer? (var-get verification-fee) tx-sender CONTRACT_OWNER))
    
    ;; Update claim verification
    (map-set identity-claims
      { identity-id: identity-id, claim-type: claim-type }
      (merge claim-data {
        verifier: (some tx-sender),
        is-verified: true
      })
    )
    
    (ok true)
  )
)

(define-public (authorize-verifier (verifier principal))
  (let ((validated-verifier verifier))
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (map-set authorized-verifiers { verifier: validated-verifier } { is-active: true })
    (ok true)))

(define-public (pause-contract)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (var-set contract-paused true)
    (ok true)))

(define-public (resume-contract)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (var-set contract-paused false)
    (ok true)))

(define-public (update-verification-fee (new-fee uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
    (asserts! (> new-fee u0) ERR_INVALID_INPUT)
    (var-set verification-fee new-fee)
    (ok true)))

(define-read-only (get-identity (identity-id uint))
  (map-get? identities { identity-id: identity-id }))

(define-read-only (get-user-identity (user principal))
  (match (map-get? user-identities { user: user })
    user-data (match (get identity-id user-data)
      identity-id (get-identity identity-id)
      none)
    none))

(define-read-only (get-claim 
  (identity-id uint)
  (claim-type (string-ascii 50))
)
  (let ((claim-data (map-get? identity-claims { identity-id: identity-id, claim-type: claim-type })))
    (match claim-data
      claim (if (get is-public claim) (some claim) none)
      none
    )
  )
)
(define-read-only (verify-identity-claim
  (identity-id uint)
  (claim-type (string-ascii 50))
)
  (match (map-get? identity-claims { identity-id: identity-id, claim-type: claim-type })
    claim-data (ok (get is-verified claim-data))
    ERR_INVALID_CLAIM
  )
)
(define-read-only (get-platform-stats)
  (ok {
    total-identities: (- (var-get next-identity-id) u1),
    verification-fee: (var-get verification-fee),
    is-paused: (var-get contract-paused)
  })
)