package bdls

import (
	"bytes"
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"github.com/skip2/go-qrcode"
	"github.com/yonggewang/bdls/blockchain/common"
	"github.com/yonggewang/bdls/blockchain/train"
	"github.com/yonggewang/bdls/blockchain/user"
	"github.com/yonggewang/bdls/global"
	"math/big"
	"net"
	"rlp"
	"sort"
	"strconv"
	"time"

	//"fmt"

	proto "github.com/gogo/protobuf/proto"
	"github.com/yonggewang/bdls/crypto/blake2b"
)

const (
	// the current BDLS protocol version,
	// version will be sent along with messages for protocol upgrading.
	ProtocolVersion = 1
	// DefaultConsensusLatency is the default propagation latency setting for
	// consensus protocol, user can adjust consensus object's latency setting
	// via Consensus.SetLatency()
	DefaultConsensusLatency = 300 * time.Millisecond

	// MaxConsensusLatency is the ceiling of latencies
	MaxConsensusLatency = 10 * time.Second
)

type (
	// State is the data to participant in consensus. This could be candidate
	// blocks in blockchain systems
	State []byte
	// StateHash = H(State)
	StateHash [blake2b.Size256]byte
)

// defaultHash is the system default hash function
func defaultHash(s State) StateHash { return blake2b.Sum256(s) }

type (
	// consensusStage defines the status of consensus automata
	consensusStage byte
)

// status definitions for consensus state machine
const (
	// stages are strictly ordered, do not change!
	stageRoundChanging consensusStage = iota
	stageLock
	stageCommit
	stageLockRelease
)

type messageTuple struct {
	StateHash StateHash    // computed while adding
	Message   *Message     // the decoded message
	Signed    *SignedProto // the encoded message with signature
}

// a sorter for messageTuple slice
type tupleSorter struct {
	tuples []messageTuple
	by     func(t1, t2 *messageTuple) bool
}

// Len implements sort.Interface
func (s *tupleSorter) Len() int { return len(s.tuples) }

// Swap implements sort.Interface
func (s *tupleSorter) Swap(i, j int) { s.tuples[i], s.tuples[j] = s.tuples[j], s.tuples[i] }

// Less implements sort.Interface
func (s *tupleSorter) Less(i, j int) bool { return s.by(&s.tuples[i], &s.tuples[j]) }

// consensusRound maintains exchanging messages in a round.
type consensusRound struct {
	c               *Consensus     // the consensus object belongs to
	Stage           consensusStage // indicates current status in consensus automata
	RoundNumber     uint64         // round number
	LockedState     State          // leader's locked state
	LockedStateHash StateHash      // hash of the leaders's locked state
	RoundChangeSent bool           // mark if the <roundchange> message of this round has sent
	CommitSent      bool           // mark if this round has sent commit message once

	// NOTE: we MUST keep the original message, to re-marshal the message may
	// result in different BITS LAYOUT, and different hash of course.
	roundChanges []messageTuple // stores <roundchange> message tuples of this round
	commits      []messageTuple // stores <commit> message tuples of this round

	// track current max proposed state in <roundchange>,  we don't have to compute this for
	// a non-leader participant, or if there're no more than 2t+1 messages for leader.
	MaxProposedState State
	MaxProposedCount int
}

// newConsensusRound creates a new round, and sets the round number
func newConsensusRound(round uint64, c *Consensus) *consensusRound {
	r := new(consensusRound)
	r.RoundNumber = round
	r.c = c
	return r
}

// AddRoundChange adds a <roundchange> message to this round, and
// checks to accept only one <roundchange> message from one participant,
// to prevent multiple proposals attack.
func (r *consensusRound) AddRoundChange(sp *SignedProto, m *Message) bool {
	for k := range r.roundChanges {
		if r.roundChanges[k].Signed.X == sp.X && r.roundChanges[k].Signed.Y == sp.Y {
			return false
		}
	}
	//将new State转发至State
	r.roundChanges = append(r.roundChanges, messageTuple{StateHash: r.c.stateHash(m.State), Message: m, Signed: sp})
	return true
}

// FindRoundChange will try to find a <roundchange> from a given participant,
// and returns index, -1 if not found
func (r *consensusRound) FindRoundChange(X PubKeyAxis, Y PubKeyAxis) int {
	for k := range r.roundChanges {
		if r.roundChanges[k].Signed.X == X && r.roundChanges[k].Signed.Y == Y {
			return k
		}
	}
	return -1
}

// RemoveRoundChange removes the given <roundchange> message at idx
func (r *consensusRound) RemoveRoundChange(idx int) {
	// swap to the end and shrink slice
	n := len(r.roundChanges) - 1
	r.roundChanges[idx], r.roundChanges[n] = r.roundChanges[n], r.roundChanges[idx]
	r.roundChanges[n] = messageTuple{} // set to nil to avoid memory leak
	r.roundChanges = r.roundChanges[:n]
}

// NumRoundChanges returns count of <roundchange> messages.
func (r *consensusRound) NumRoundChanges() int { return len(r.roundChanges) }

// SignedRoundChanges converts and returns []*SignedProto(as slice)
func (r *consensusRound) SignedRoundChanges() []*SignedProto {
	proof := make([]*SignedProto, 0, len(r.roundChanges))
	for k := range r.roundChanges {
		proof = append(proof, r.roundChanges[k].Signed)
	}
	return proof
}

// RoundChangeStates returns all non-nil state in exchanging round change message as slice
func (r *consensusRound) RoundChangeStates() []State {
	states := make([]State, 0, len(r.roundChanges))
	for k := range r.roundChanges {
		if r.roundChanges[k].Message.State != nil {
			states = append(states, r.roundChanges[k].Message.State)
		}
	}
	return states
}

// AddCommit adds decoded messages along with its original signed message unchanged,
// also, messages will be de-duplicated to prevent multiple proposals attack.
func (r *consensusRound) AddCommit(sp *SignedProto, m *Message) bool {
	for k := range r.commits {
		if r.commits[k].Signed.X == sp.X && r.commits[k].Signed.Y == sp.Y {
			return false
		}
	}
	r.commits = append(r.commits, messageTuple{StateHash: r.c.stateHash(m.State), Message: m, Signed: sp})
	return true
}

// NumCommitted counts <commit> messages which points to what the leader has locked.
func (r *consensusRound) NumCommitted() int {
	var count int
	for k := range r.commits {
		if r.commits[k].StateHash == r.LockedStateHash {
			count++
		}
	}
	return count
}

// SignedCommits converts and returns []*SignedProto
func (r *consensusRound) SignedCommits() []*SignedProto {
	proof := make([]*SignedProto, 0, len(r.commits))
	for k := range r.commits {
		proof = append(proof, r.commits[k].Signed)
	}
	return proof
}

// GetMaxProposed finds the most agreed-on non-nil state, if these is any.
func (r *consensusRound) GetMaxProposed() (s State, count int) {
	if len(r.roundChanges) == 0 {
		return nil, 0
	}

	// sort by hash, to group identical hashes together
	// O(n*logn)
	sorter := tupleSorter{
		tuples: r.roundChanges,
		// sort by it's hash lexicographically
		by: func(t1, t2 *messageTuple) bool {
			return bytes.Compare(t1.StateHash[:], t2.StateHash[:]) < 0
		},
	}
	sort.Sort(&sorter)

	// find the maximum occurred hash
	// O(n)
	maxCount := 1
	maxState := r.roundChanges[0]
	curCount := 1

	n := len(r.roundChanges)
	for i := 1; i < n; i++ {
		if r.roundChanges[i].StateHash == r.roundChanges[i-1].StateHash {
			curCount++
		} else {
			if curCount > maxCount {
				maxCount = curCount
				maxState = r.roundChanges[i-1]
			}
			curCount = 1
		}
	}

	// if the last hash is the maximum occurred
	if curCount > maxCount {
		maxCount = curCount
		maxState = r.roundChanges[n-1]
	}

	return maxState.Message.State, maxCount
}

// Consensus implements a deterministic BDLS consensus protocol.
//
// It has no internal clocking or IO, and no parallel processing.
// The runtime behavior is predictable and deterministic.
// Users should write their own timing and IO function to feed in
// messages and ticks to trigger timeouts.
type Consensus struct {
	latestState  State        // latest confirmed state of current height
	latestHeight uint64       // latest confirmed height
	latestRound  uint64       // latest confirmed round
	latestProof  *SignedProto // latest <decide> message to prove the state

	unconfirmed []State // data awaiting to be confirmed at next height

	rounds       list.List       // all rounds at next height(consensus round in progress)
	currentRound *consensusRound // current round which has collected >=2t+1 <roundchange>

	// timeouts in different stage
	rcTimeout          time.Time // roundchange status timeout: Delta_0
	lockTimeout        time.Time // lock status timeout: Delta_1
	commitTimeout      time.Time // commit status timeout: Delta_2
	lockReleaseTimeout time.Time // lock-release status timeout: Delta_3

	// locked states, along with its signatures and hashes in tuple
	locks []messageTuple

	// the StateCompare function from configs
	stateCompare func(State, State) int
	// the StateValidate function from configs
	stateValidate func(State) bool
	// message in callback
	messageValidator func(c *Consensus, m *Message, sp *SignedProto) bool
	// message out callback
	messageOutCallback func(m *Message, sp *SignedProto)
	// public key to identity function
	pubKeyToIdentity func(pubkey *ecdsa.PublicKey) Identity

	// the StateHash function to identify a state
	stateHash func(State) StateHash
	//send to superior to request consensus
	sendToSuperior func(bts []byte)
	//send to subordinate to agree consensus
	sendToSubordinates func(bts []byte)
	// private key
	privateKey *ecdsa.PrivateKey
	// my publickey coodinate
	identity Identity
	// curve retrieved from private key
	curve elliptic.Curve

	// transmission delay
	latency time.Duration

	// all connected peers
	peers []PeerInterface
	//superior PeerInterface
	// participants is the consensus group, current leader is r % quorum
	participants []Identity
	other        []Identity
	// count num of individual identities
	numIdentities int //[YONGGE WANG' comments:] make sure this is synchronized with []Identity

	// set to true to enable <commit> message unicast
	enableCommitUnicast bool

	// NOTE: fixed leader for testing purpose
	fixedLeader *Identity

	// broadcasting messages being sent to myself
	loopback [][]byte

	// the last message which caused round change
	lastRoundChangeProof []*SignedProto
}

// NewConsensus creates a BDLS consensus object to participant in consensus procedure,
// the consensus object returned is data in memory without goroutines or other
// non-deterministic objects, and errors will be returned if there is problem, with
// the given configs.
func NewConsensus(config *Config) (*Consensus, error) {
	err := VerifyConfig(config)
	if err != nil {
		return nil, err
	}

	c := new(Consensus)
	c.init(config)
	return c, nil
}

// init consensus with configs
func (c *Consensus) init(config *Config) {
	// setting current state & height
	c.latestHeight = config.CurrentHeight
	c.participants = config.Participants
	c.stateCompare = config.StateCompare
	c.stateValidate = config.StateValidate
	c.messageValidator = config.MessageValidator
	c.messageOutCallback = config.MessageOutCallback
	c.privateKey = config.PrivateKey
	c.pubKeyToIdentity = config.PubKeyToIdentity
	c.enableCommitUnicast = config.EnableCommitUnicast

	// if configs has not set hash function, use the default
	if c.stateHash == nil {
		c.stateHash = defaultHash
	}
	// if configs has not set public key to identity function, use the default
	if c.pubKeyToIdentity == nil {
		c.pubKeyToIdentity = DefaultPubKeyToIdentity
	}
	c.identity = c.pubKeyToIdentity(&c.privateKey.PublicKey)
	c.curve = c.privateKey.Curve

	// initial default parameters settings
	c.latency = DefaultConsensusLatency

	// and initiated the first <roundchange> proposal
	c.switchRound(0)
	c.currentRound.Stage = stageRoundChanging
	c.broadcastRoundChange()
	// set rcTimeout to lockTimeout
	c.rcTimeout = config.Epoch.Add(c.roundchangeDuration(0))

	// count number of individual identites
	ids := make(map[Identity]bool)
	for _, id := range c.participants {
		ids[id] = true
	}
	c.numIdentities = len(ids)
}

//  calculates roundchangeDuration
func (c *Consensus) roundchangeDuration(round uint64) time.Duration {
	d := 2 * c.latency * (1 << round)
	if d > MaxConsensusLatency {
		d = MaxConsensusLatency
	}
	return d
}

//  calculates collectDuration
func (c *Consensus) collectDuration(round uint64) time.Duration {
	d := 2 * c.latency * (1 << round)
	if d > MaxConsensusLatency {
		d = MaxConsensusLatency
	}
	return d
}

//  calculates lockDuration
func (c *Consensus) lockDuration(round uint64) time.Duration {
	d := 4 * c.latency * (1 << round)
	if d > MaxConsensusLatency {
		d = MaxConsensusLatency
	}
	return d
}

// calculates commitDuration
func (c *Consensus) commitDuration(round uint64) time.Duration {
	d := 2 * c.latency * (1 << round)
	if d > MaxConsensusLatency {
		d = MaxConsensusLatency
	}
	return d
}

// calculates lockReleaseDuration
func (c *Consensus) lockReleaseDuration(round uint64) time.Duration {
	d := 2 * c.latency * (1 << round)
	if d > MaxConsensusLatency {
		d = MaxConsensusLatency
	}
	return d
}

// maximalLocked finds the maximum locked data in this round,
// with regard to StateCompare function in configs.
func (c *Consensus) maximalLocked() State {
	if len(c.locks) > 0 {
		maxState := c.locks[0].Message.State
		for i := 1; i < len(c.locks); i++ {
			if c.stateCompare(maxState, c.locks[i].Message.State) < 0 {
				maxState = c.locks[i].Message.State
			}
		}
		return maxState
	}
	return nil
}

// maximalUnconfirmed finds the maximal unconfirmed data with,
// regard to the StateCompare function in configs.
func (c *Consensus) maximalUnconfirmed() State {
	if len(c.unconfirmed) > 0 {
		maxState := c.unconfirmed[0]
		for i := 1; i < len(c.unconfirmed); i++ {
			if c.stateCompare(maxState, c.unconfirmed[i]) < 0 {
				maxState = c.unconfirmed[i]
			}
		}
		return maxState
	}
	return nil
}

// verifyMessage verifies message signature against it's <r,s> & <x,y>,
// and also checks if the signer is a valid participant.
// returns it's decoded 'Message' object if signature has proved authentic.
// returns nil and error if message has not been correctly signed or from an unknown participant.
func (c *Consensus) verifyMessage(signed *SignedProto) (*Message, error) {
	if signed == nil {
		return nil, ErrMessageIsEmpty
	}

	// check signer's identity, all participants have proven
	// public key
	knownParticipants := false
	coord := c.pubKeyToIdentity(signed.PublicKey(c.curve))
	for k := range c.participants {
		if coord == c.participants[k] {
			knownParticipants = true
		}
	}
	for k := range c.other {
		if coord == c.other[k] {
			knownParticipants = true
		}
	}
	if !knownParticipants {
		return nil, ErrMessageUnknownParticipant
	}

	/*
		// public key validation
		p := defaultCurve.Params().P
		x := new(big.Int).SetBytes(signed.X[:])
		y := new(big.Int).SetBytes(signed.Y[:])
		if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
			return nil, ErrMessageSignature
		}
		if !defaultCurve.IsOnCurve(x, y) {
			return nil, ErrMessageSignature
		}
	*/

	// as public key is proven , we don't have to verify the public key
	if !signed.Verify(c.curve) {
		return nil, ErrMessageSignature
	}

	// decode message
	m := new(Message)
	err := proto.Unmarshal(signed.Message, m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// verify <roundchange> message
func (c *Consensus) verifyRoundChangeMessage(m *Message) error {
	// check message height
	if m.Height != c.latestHeight+1 {
		return ErrRoundChangeHeightMismatch
	}

	// check round in protocol
	if m.Round < c.currentRound.RoundNumber {
		return ErrRoundChangeRoundLower
	}

	// state data validation for non-null <roundchange>
	if m.State != nil {
		if !c.stateValidate(m.State) {
			return ErrRoundChangeStateValidation
		}
	}
	//update
	//c.Propose(m.State)
	return nil
}

// verifyLockMessage verifies proofs from <lock> messages,
// a lock message must contain at least 2t+1 individual <roundchange>
// messages on B'
func (c *Consensus) verifyLockMessage(m *Message, signed *SignedProto) error {
	// check message height
	if m.Height != c.latestHeight+1 {
		return ErrLockHeightMismatch
	}

	// check round in protocol
	if m.Round < c.currentRound.RoundNumber {
		return ErrLockRoundLower
	}

	// a <lock> message from leader MUST include data along with the message
	if m.State == nil {
		return ErrLockEmptyState
	}

	// state data validation
	if !c.stateValidate(m.State) {
		return ErrLockStateValidation
	}

	// make sure this message has been signed by the leader
	leaderKey := c.roundLeader(m.Round)
	if c.pubKeyToIdentity(signed.PublicKey(c.curve)) != leaderKey {
		return ErrLockNotSignedByLeader
	}

	// validate proofs enclosed in the message one by one
	rcs := make(map[Identity]State)
	for _, proof := range m.Proof {
		// first we need to verify the signature,and identity of this proof
		mProof, err := c.verifyMessage(proof)
		if err != nil {
			if err == ErrMessageUnknownParticipant {
				return ErrLockProofUnknownParticipant
			}
			return err
		}

		// then we need to check the message type
		if mProof.Type != MessageType_RoundChange {
			return ErrLockProofTypeMismatch
		}

		// and we also need to check the height & round field,
		// all <roundchange> messages must be in the same round as the lock message
		if mProof.Height != m.Height {
			return ErrLockProofHeightMismatch
		}

		if mProof.Round != m.Round {
			return ErrLockProofRoundMismatch
		}

		// state data validation in proofs
		if mProof.State != nil {
			if !c.stateValidate(mProof.State) {
				return ErrLockProofStateValidation
			}
		}

		// use map to guarantee we will only accept at most 1 message from one
		// individual participant
		rcs[c.pubKeyToIdentity(proof.PublicKey(c.curve))] = mProof.State
	}

	// count individual proofs to B', which has already guaranteed to be the maximal one.
	var numValidateProofs int
	mHash := c.stateHash(m.State)
	for _, v := range rcs {
		if c.stateHash(v) == mHash { // B'
			numValidateProofs++
		}
	}

	// check if valid proofs count is less that 2*t+1
	if numValidateProofs < 2*c.t()+1 {
		return ErrLockProofInsufficient
	}
	return nil
}

// verifyLockReleaseMessage will verify LockRelease field in a <lock-release> messages,
// returns the embedded <lock> message if valid
func (c *Consensus) verifyLockReleaseMessage(signed *SignedProto) (*Message, error) {
	// not in lock release status, omit this message
	if c.currentRound.Stage != stageLockRelease {
		return nil, ErrLockReleaseStatus
	}

	// verify and decode the embedded lock message
	lockmsg, err := c.verifyMessage(signed)
	if err != nil {
		return nil, err
	}

	// recursively verify proofs in lock message
	err = c.verifyLockMessage(lockmsg, signed)
	if err != nil {
		return nil, err
	}
	return lockmsg, nil
}

// verifySelectMessage verifies proofs from <select> message,
// <select> message MUST contain at least 2t+1 individual messages, but
// proofs from <select> message MUST NOT contain >= 2t+1 individual
// <roundchange> messages related to B' at the same time.
func (c *Consensus) verifySelectMessage(m *Message, signed *SignedProto) error {
	// check message height
	if m.Height != c.latestHeight+1 {
		return ErrSelectHeightMismatch
	}

	// check round in protocol
	if m.Round < c.currentRound.RoundNumber {
		return ErrSelectRoundLower
	}

	// state data validation for non-null <select>
	if m.State != nil {
		if !c.stateValidate(m.State) {
			return ErrSelectStateValidation
		}
	}

	// make sure this message has been signed by the leader
	leaderKey := c.roundLeader(m.Round)
	if c.pubKeyToIdentity(signed.PublicKey(c.curve)) != leaderKey {
		return ErrSelectNotSignedByLeader
	}

	rcs := make(map[Identity]State)
	for _, proof := range m.Proof {
		mProof, err := c.verifyMessage(proof)
		if err != nil {
			if err == ErrMessageUnknownParticipant {
				return ErrSelectProofUnknownParticipant
			}
			return err
		}

		if mProof.Type != MessageType_RoundChange {
			return ErrSelectProofTypeMismatch
		}

		if mProof.Height != m.Height {
			return ErrSelectProofHeightMismatch
		}

		if mProof.Round != m.Round {
			return ErrSelectProofRoundMismatch
		}

		// state data validation in proofs
		if mProof.State != nil {
			if !c.stateValidate(mProof.State) {
				return ErrSelectProofStateValidation
			}
		}

		// we also need to check the B'' selected by leader is the maximal one,
		// if data has been proposed.
		if mProof.State != nil && m.State != nil {
			if c.stateCompare(m.State, mProof.State) < 0 {
				return ErrSelectProofNotTheMaximal
			}
		}

		// we also stores B'' == NULL for counting
		rcs[c.pubKeyToIdentity(proof.PublicKey(c.curve))] = mProof.State
	}

	// check we have at least 2*t+1 proof
	if len(rcs) < 2*c.t()+1 {
		return ErrSelectProofInsufficient
	}

	// count maximum proofs with B' != NULL with identical data hash,
	// to prevent leader cheating on select.
	dataProposals := make(map[StateHash]int)
	for _, data := range rcs {
		if data != nil {
			dataProposals[c.stateHash(data)]++
		}
	}

	// if m.State == NULL, but there are non-NULL proofs,
	// the leader may be cheating
	if m.State == nil && len(dataProposals) > 0 {
		return ErrSelectStateMismatch
	}

	// find the highest proposed B'(not NULL)
	var maxProposed int
	for _, count := range dataProposals {
		if count > maxProposed {
			maxProposed = count
		}
	}

	// if these are more than 2*t+1 valid <roundchange> proofs to B',
	// this also suggests that the leader may cheat.
	if maxProposed >= 2*c.t()+1 {
		return ErrSelectProofExceeded
	}

	return nil
}

// verifyCommitMessage will check if this message is acceptable to consensus
func (c *Consensus) verifyCommitMessage(m *Message) error {
	// the leader has to be in COMMIT status to process this message
	if c.currentRound.Stage != stageCommit {
		return ErrCommitStatus
	}

	// a <commit> message from participants MUST includes data along with the message
	if m.State == nil {
		return ErrCommitEmptyState
	}

	// state data validation
	if !c.stateValidate(m.State) {
		return ErrCommitStateValidation
	}

	// check height
	if m.Height != c.latestHeight+1 {
		return ErrCommitHeightMismatch
	}

	// only accept commits to current round
	if c.currentRound.RoundNumber != m.Round {
		return ErrCommitRoundMismatch
	}

	// check state match
	if c.stateHash(m.State) != c.currentRound.LockedStateHash {
		return ErrCommitStateMismatch
	}

	return nil
}

// ValidateDecideMessage validates a <decide> message for non-participants,
// the consensus core must be correctly initialized to validate.
// the targetState is to compare the target state enclosed in decide message
func (c *Consensus) ValidateDecideMessage(bts []byte, targetState []byte) error {
	signed, err := DecodeSignedMessage(bts)
	if err != nil {
		return err
	}

	return c.validateDecideMessage(signed, targetState)
}

// DecodeSignedMessage decodes a binary representation of signed consensus message.
func DecodeSignedMessage(bts []byte) (*SignedProto, error) {
	signed := new(SignedProto)
	err := proto.Unmarshal(bts, signed)
	if err != nil {
		return nil, err
	}
	return signed, nil
}

// DecodeMessage decodes a binary representation of consensus message.
func DecodeMessage(bts []byte) (*Message, error) {
	msg := new(Message)
	err := proto.Unmarshal(bts, msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// validateDecideMessage validates a decoded <decide> message for non-participants,
// the consensus core must be correctly initialized to validate.
func (c *Consensus) validateDecideMessage(signed *SignedProto, targetState []byte) error {
	// check message version
	if signed.Version != ProtocolVersion {
		return ErrMessageVersion
	}

	// check message signature & qualifications
	m, err := c.verifyMessage(signed)
	if err != nil {
		return err
	}

	// compare state
	if !bytes.Equal(m.State, targetState) {
		return ErrMismatchedTargetState
	}

	// verify decide message
	if m.Type == MessageType_Decide {
		err := c.verifyDecideMessage(m, signed)
		if err != nil {
			return err
		}
		return nil
	}
	return ErrMessageUnknownMessageType
}

// verifyDecideMessage verifies proofs from <decide> message, which MUST
// contain at least 2t+1 individual <commit> messages to B'.
func (c *Consensus) verifyDecideMessage(m *Message, signed *SignedProto) error {
	// a <decide> message from leader MUST include data along with the message
	if m.State == nil {
		return ErrDecideEmptyState
	}

	// state data validation
	if !c.stateValidate(m.State) {
		return ErrDecideStateValidation
	}

	// check height
	if m.Height <= c.latestHeight {
		return ErrDecideHeightLower
	}

	// make sure this message has been signed by the leader
	leaderKey := c.roundLeader(m.Round)
	if c.pubKeyToIdentity(signed.PublicKey(c.curve)) != leaderKey {
		return ErrDecideNotSignedByLeader
	}

	commits := make(map[Identity]State)
	for _, proof := range m.Proof {
		mProof, err := c.verifyMessage(proof)
		if err != nil {
			if err == ErrMessageUnknownParticipant {
				return ErrDecideProofUnknownParticipant
			}
			return err
		}

		if mProof.Type != MessageType_Commit {
			return ErrDecideProofTypeMismatch
		}

		if mProof.Height != m.Height {
			return ErrDecideProofHeightMismatch
		}

		if mProof.Round != m.Round {
			return ErrDecideProofRoundMismatch
		}

		if !c.stateValidate(mProof.State) {
			return ErrDecideProofStateValidation
		}

		// state data validation in proofs
		if mProof.State != nil {
			if !c.stateValidate(mProof.State) {
				return ErrSelectProofStateValidation
			}
		}

		commits[c.pubKeyToIdentity(proof.PublicKey(c.curve))] = mProof.State
	}

	// count proofs to m.State
	var numValidateProofs int
	mHash := c.stateHash(m.State)
	for _, v := range commits {
		if c.stateHash(v) == mHash {
			numValidateProofs++
		}
	}

	// check to see if the message has at least 2*t+1 <commit> valid proofs,
	// if not, the leader may cheat.
	if numValidateProofs < 2*c.t()+1 {
		return ErrDecideProofInsufficient
	}
	return nil
}

// broadcastRoundChange will broadcast <roundchange> messages on
// current round, taking the maximal B' from unconfirmed data.
func (c *Consensus) broadcastRoundChange() {
	// if <roundchange> has sent in this round,
	// then just ignore. But if we are in roundchanging state,
	// we should send repeatedly, for boostrap process.
	if c.currentRound.RoundChangeSent && c.currentRound.Stage != stageRoundChanging {
		return
	}

	// first we need to check if there is any locked data,
	// locked data must be sent if there is any.
	data := c.maximalLocked()
	if data == nil {
		// if there's none locked data, we pick the maximum unconfirmed data to propose
		data = c.maximalUnconfirmed()
		// if still null, return
		if data == nil {
			return
		}
	}
	var m Message
	m.Type = MessageType_RoundChange
	m.Height = c.latestHeight + 1
	m.Round = c.currentRound.RoundNumber
	m.State = data
	c.broadcast(&m)
	c.currentRound.RoundChangeSent = true
	//log.Println("broadcast:<roundchange>")
}

// broadcastLock will broadcast <lock> messages on current round,
// the currentRound should have a chosen data in this round.
func (c *Consensus) broadcastLock() {
	var m Message
	m.Type = MessageType_Lock
	m.Height = c.latestHeight + 1
	m.Round = c.currentRound.RoundNumber
	m.State = c.currentRound.LockedState
	m.Proof = c.currentRound.SignedRoundChanges()
	c.broadcast(&m)
	//log.Println("broadcast:<lock>")
}

// broadcastLockRelease will broadcast <lock-release> messages,
func (c *Consensus) broadcastLockRelease(signed *SignedProto) {
	var m Message
	m.Type = MessageType_LockRelease
	m.Height = c.latestHeight + 1
	m.Round = c.currentRound.RoundNumber
	m.LockRelease = signed
	c.broadcast(&m)
	//log.Println("broadcast:<lock-release>")
}

// broadcastSelect will broadcast a <select> message by the leader,
// from current round with <roundchange> proofs.
func (c *Consensus) broadcastSelect() {
	var m Message
	m.Type = MessageType_Select
	m.Height = c.latestHeight + 1
	m.Round = c.currentRound.RoundNumber
	m.State = c.maximalUnconfirmed() // B' may be NULL
	m.Proof = c.currentRound.SignedRoundChanges()
	c.broadcast(&m)
	//log.Println("broadcast:<select>", m.State)
}

// broadcastDecide will broadcast a <decide> message by the leader,
// from current round with <commit> proofs.
func (c *Consensus) broadcastDecide() *SignedProto {
	var m Message
	m.Type = MessageType_Decide
	m.Height = c.latestHeight + 1
	m.Round = c.currentRound.RoundNumber
	m.State = c.currentRound.LockedState
	m.Proof = c.currentRound.SignedCommits()
	return c.broadcast(&m)
	//log.Println("broadcast:<decide>")
}

// broadcastResync will broadcast a <resync> message by the leader,
// from current round with <roundchange> proofs.
func (c *Consensus) broadcastResync() {
	if c.lastRoundChangeProof == nil {
		return
	}

	var m Message
	m.Type = MessageType_Resync
	// we only care about <roundchange> messages in resync
	m.Proof = c.lastRoundChangeProof
	c.broadcast(&m)
	//log.Println("broadcast:<resync>")
}

// sendCommit will send a <commit> message by participants to the leader
// from received <lock> message.
func (c *Consensus) sendCommit(msgLock *Message) {
	if c.currentRound.CommitSent {
		return
	}

	var m Message
	m.Type = MessageType_Commit
	m.Height = msgLock.Height // h
	m.Round = msgLock.Round   // r
	m.State = msgLock.State   // B'j
	if c.enableCommitUnicast {
		c.sendTo(&m, c.roundLeader(m.Round))
	} else {
		c.broadcast(&m)
	}
	c.currentRound.CommitSent = true
	//log.Println("send:<commit>")
}

//将消息发送至当前Leader
func (c *Consensus) sendLeader(m *Message) *SignedProto {
	//sign
	sp := new(SignedProto)
	sp.Version = ProtocolVersion
	sp.Sign(m, c.privateKey)
	// message callback
	if c.messageOutCallback != nil {
		c.messageOutCallback(m, sp)
	}
	// protobuf marshalling
	out, err := proto.Marshal(sp)
	if err != nil {
		panic(err)
	}
	if len(c.peers) == 0 {
		return nil
	}
	fmt.Println("发送至：", c.peers[int(m.Round)%len(c.peers)].RemoteAddr())
	for _, peer := range c.peers {
		fmt.Println(peer.RemoteAddr())
	}
	// send to leader
	c.peers[int(m.Round)%len(c.peers)].Send(out)
	// we also need to send this message to myself
	if m.Type != MessageType_ConsensusInfo {
		c.loopback = append(c.loopback, out)
	} else {
		//将信息池清空
		fmt.Println("清空信息sendLeader")
		global.RWMutexConsensusPool.Lock()
		global.ConsensusInfoPool = &global.BlockInfos{}
		global.RWMutexConsensusPool.Unlock()
	}
	return sp
}

// broadcast signs the message with private key before broadcasting to all peers.
func (c *Consensus) broadcast(m *Message) *SignedProto {
	// sign
	sp := new(SignedProto)
	sp.Version = ProtocolVersion
	sp.Sign(m, c.privateKey)

	// message callback
	if c.messageOutCallback != nil {
		c.messageOutCallback(m, sp)
	}
	// protobuf marshalling
	out, err := proto.Marshal(sp)
	if err != nil {
		panic(err)
	}
	// send to peers one by one
	for _, peer := range c.peers {
		err = peer.Send(out)
	}

	// we also need to send this message to myself
	c.loopback = append(c.loopback, out)
	return sp
}

// sendTo signs the message with private key before transmitting to the peer.
func (c *Consensus) sendTo(m *Message, leader Identity) {
	// sign
	sp := new(SignedProto)
	sp.Version = ProtocolVersion
	sp.Sign(m, c.privateKey)

	// message callback
	if c.messageOutCallback != nil {
		c.messageOutCallback(m, sp)
	}

	// protobuf marshalling
	out, err := proto.Marshal(sp)
	if err != nil {
		panic(err)
	}

	// we need to send this message to myself (via loopback) if i'm the leader
	if leader == c.identity {
		c.loopback = append(c.loopback, out)
		return
	}
	//fmt.Println("ready to send")
	// otherwise, find and transmit to the leader
	for _, peer := range c.peers {
		if pk := peer.GetPublicKey(); pk != nil {
			coord := c.pubKeyToIdentity(pk)
			if coord == leader {
				//fmt.Println("begin send to leader")
				// we do not return here to avoid missing re-connected peer.
				err = peer.Send(out)
				global.MyError(err)
				//fmt.Println(err)
				if m.Type == MessageType_ConsensusInfo {
					fmt.Println("已经向Leader发送待共识信息...")
					//将信息池清空
					global.RWMutexConsensusPool.Lock()
					global.ConsensusInfoPool = &global.BlockInfos{}
					global.RWMutexConsensusPool.Unlock()
					break
				}
				if m.Type == MessageType_BlocksInfo {
					fmt.Println("已经向Leader发送待共识区块...")
					//将信息池清空
					global.RWMutexBlock.Lock()
					global.Blocks.Blocks = [][]byte{}
					global.RWMutexBlock.Unlock()
					break
				}
			}
		}
	}
}

// propagate broadcasts signed message UNCHANGED to peers.
func (c *Consensus) propagate(bts []byte) {
	// send to peers one by one
	for _, peer := range c.peers {
		_ = peer.Send(bts)
	}
}

// getRound returns the consensus round with given idx, create one if not exists
// if purgeLower has set, all lower rounds will be cleared
func (c *Consensus) getRound(idx uint64, purgeLower bool) *consensusRound {
	var next *list.Element
	for elem := c.rounds.Front(); elem != nil; elem = next {
		next = elem.Next()
		r := elem.Value.(*consensusRound)

		if r.RoundNumber < idx { // lower round
			// if remove flag has set, remove this round safely,
			// usually used by switchRound
			if purgeLower {
				c.rounds.Remove(elem)
			}
			continue
		} else if idx < r.RoundNumber { // higher round
			// insert a new round entry before this round
			// to make sure the list is ordered
			newr := newConsensusRound(idx, c)
			c.rounds.InsertBefore(newr, elem)
			return newr
		} else if r.RoundNumber == idx { // found entry
			return r
		}
	}

	// looped to the end, we create and push back
	newr := newConsensusRound(idx, c)
	c.rounds.PushBack(newr)
	return newr
}

// lockRelease updates locks while entering lock-release status
// and will broadcast its max B' if there is any.
func (c *Consensus) lockRelease() {
	// only keep the locked B' with the max round number
	// while switching to lock-release status
	if len(c.locks) > 0 {
		max := c.locks[0]
		for i := 1; i < len(c.locks); i++ {
			if max.Message.Round < c.locks[i].Message.Round {
				max = c.locks[i]
			}
		}
		c.locks = []messageTuple{max}
		c.broadcastLockRelease(max.Signed)
	}
}

// switchRound sets currentRound to the given idx, and creates new a consensusRound
// if it's not been initialized.
// and all lower rounds will be cleared while switching.
func (c *Consensus) switchRound(round uint64) { c.currentRound = c.getRound(round, true) }

// roundLeader returns leader's identity for a given round
func (c *Consensus) roundLeader(round uint64) Identity {
	// NOTE: fixed leader is for testing
	if c.fixedLeader != nil {
		return *c.fixedLeader
	}
	return c.participants[int(round)%len(c.participants)]
}

// heightSync changes current height to the given height with state
// resets all fields to this new height.
func (c *Consensus) heightSync(height uint64, round uint64, s State, now time.Time) {
	c.latestHeight = height      // set height
	c.latestRound = round        // set round
	c.latestState = s            // set state
	c.currentRound = nil         // clean current round pointer
	c.lastRoundChangeProof = nil // clean round change proof
	c.rounds.Init()              // clean all round
	c.locks = nil                // clean locks
	c.unconfirmed = nil          // clean all unconfirmed states from previous heights
	c.switchRound(0)             // start new round at new height
	c.currentRound.Stage = stageRoundChanging
	//如果是一级节点，需要将共识结果向下级进行广播
	if global.StatusLogin == global.BureauStatus {
		fmt.Println("铁路局层内共识完毕，开始通知列车节点区块入链...")
		blocks := global.MapBlocksData[height]
		delete(global.MapBlocksData, height)
		go c.sendToSubordinates(blocks)
		//包含多个区块信息
		go UpdateBlockchain(blocks)
	}
}
func addUserInfo(account string, key *big.Int) {
	port := global.CurrentId
	fileId := port
	if global.StatusLogin == global.TrainStatus {
		//待注册用户为乘务员节点
		fileId++
	} else {
		//待注册用户为列车节点
		num := len(global.Cfg.Next)
		port += (num + 1) * 50
		fileId = port
		//生成其配置文件
	}
	//生成二维码
	qrcode.WriteFile(key.String()+"|"+strconv.Itoa(port), qrcode.Medium, 256, global.QrCodePath+strconv.Itoa(fileId)+".png")

}
func addBlock(bts []byte) {
	//return
	blockData := global.DeserializeBlockData(bts)
	blockInfos := global.DeserializeBlockInfos(blockData.Info)
	var flagUser, flagTrain bool
	for i, info := range blockInfos.Infos {
		if info.Type == global.BlockchainTrain {
			infoTrain := &common.InfoTrain{}
			err := rlp.DecodeBytes(info.Data, infoTrain)
			global.MyError(err)
			fmt.Printf("第%d个高铁信息如下：\n", i+1)
			infoTrain.PrintInfoTrain()
			common.RWTrainPool.Lock()
			common.InfoTrainPool = append(common.InfoTrainPool, infoTrain)
			train.MapOtherTrain[hex.EncodeToString(infoTrain.PublicKey)] = infoTrain.Hash
			common.RWTrainPool.Unlock()
			flagTrain = true
		}
		if info.Type == global.BlockchainUser {
			infoUser := &common.InfoUser{}
			err := rlp.DecodeBytes(info.Data, infoUser)
			global.MyError(err)
			account := hex.EncodeToString(infoUser.Account)
			if _, ok := global.MapUserData[account]; ok {
				//当前节点存在待入链用户秘钥
				key := global.MapUserData[account]
				fmt.Printf("第%d个账户信息如下：\n", i+1)
				infoUser.PrintInfoUser()
				fmt.Println("该账户的D值为：", key)
				go addUserInfo(account, key)
				delete(global.MapUserData, account)
			}
			//common.Map_InfoUser[address] = infoUser
			common.RWUserPool.Lock()
			user.MapRootUser[hex.EncodeToString(infoUser.PublicKey)] = infoUser.Hash
			common.InfoUserPool = append(common.InfoUserPool, infoUser)
			common.RWUserPool.Unlock()
			flagUser = true
		}
	}
	//添加区块
	if flagUser {
		go user.AddBlock(blockData.TimeStamp)
	}
	if flagTrain {
		go train.AddBlock(blockData.TimeStamp)
	}
	if flagUser {
		<-global.ChBlockchainUser
	}
	if flagTrain {
		<-global.ChBlockchainTrain
	}
}
func UpdateBlockchain(blockDataBytes []byte) {
	blocks := global.DeserializeBlockDataInfos(blockDataBytes)
	for _, block := range blocks.Blocks {
		fmt.Println(len(block), "即将写入区块...")
		go addBlock(block)
	}
}

// t calculates (n-1)/3
func (c *Consensus) t() int { return (c.numIdentities - 1) / 3 }

// Propose adds a new state to unconfirmed queue to participate in
// consensus at next height.
func (c *Consensus) Propose(s State) {
	if s == nil {
		return
	}

	sHash := c.stateHash(s)
	for k := range c.unconfirmed {
		if c.stateHash(c.unconfirmed[k]) == sHash {
			return
		}
	}
	c.unconfirmed = append(c.unconfirmed, s)
}

// ReceiveMessage processes incoming consensus messages, and returns error
// if message cannot be processed for some reason.
func (c *Consensus) ReceiveMessage(bts []byte, now time.Time) (err error) {
	// messages broadcasted to myself may be queued recursively, and
	// we only process these messages in defer to avoid side effects
	// while processing.
	defer func() {
		for len(c.loopback) > 0 {
			bts := c.loopback[0]
			c.loopback = c.loopback[1:]
			// NOTE: message directed to myself ignores error.
			_ = c.receiveMessage(bts, now)
		}
	}()
	return c.receiveMessage(bts, now)
}

func (c *Consensus) receiveMessage(bts []byte, now time.Time) error {
	// unmarshal signed message
	signed := new(SignedProto)
	err := proto.Unmarshal(bts, signed)
	if err != nil {
		return err
	}

	// check message version
	if signed.Version != ProtocolVersion {
		return ErrMessageVersion
	}

	// check message signature & qualifications
	m, err := c.verifyMessage(signed)
	if err != nil {
		return err
	}

	// callback for incoming message
	if c.messageValidator != nil {
		if !c.messageValidator(c, m, signed) {
			return ErrMessageValidator
		}
	}
	// message switch
	switch m.Type {
	case MessageType_ConsensusInfo:
		//收到其他节点发来的共识消息
		//首先判断该账户是否是Leader
		leaderKey := c.roundLeader(c.currentRound.RoundNumber)
		if leaderKey == c.identity {
			//如果该节点是Leader,将收到的共识信息加入到本地consensusinfopool
			err := global.SetConsensusInfoBytes(m.State)
			global.MyError(err)
			fmt.Println("收到来自其他节点的共识信息，已加入共识信息池...")
			return err
		} else {
			fmt.Println("我不是Leader，你发错了...")
		}
	case MessageType_BlocksInfo:
		//首先判断该账户是否是Leader
		leaderKey := c.roundLeader(c.currentRound.RoundNumber)
		if leaderKey == c.identity {
			//如果该节点是Leader,将收到的区块信息加入到本地BlocksPool
			err := global.SetBlocksInfoBytes(m.State)
			global.MyError(err)
			return err
		}
	case MessageType_Nop:
		// nop does nothing
		return nil
	case MessageType_RoundChange:
		err := c.verifyRoundChangeMessage(m)
		if err != nil {
			return err
		}
		// for <roundchange> message, we need to find in each round
		// to check if this sender has already sent <roundchange>
		// we only keep the message from the max round.
		// NOTE: we don't touch current round to prevent removing
		// valid proofs.
		// NOTE: the total messages are bounded to max 2*participants
		// at any time, so the loop has O(n) time complexity
		var next *list.Element
		for elem := c.rounds.Front(); elem != nil; elem = next {
			next = elem.Next()
			cr := elem.Value.(*consensusRound)
			if idx := cr.FindRoundChange(signed.X, signed.Y); idx != -1 { // located!
				if m.Round == c.currentRound.RoundNumber { // don't remove now!
					continue
				} else if cr.RoundNumber > m.Round {
					// existing message is higher than incoming message,
					// just ignore.
					return nil
				} else if cr.RoundNumber < m.Round {
					// existing message is lower than incoming message,
					// remove the existing message from this round.
					cr.RemoveRoundChange(idx)
					// if no message remained in this round, release
					// the round resources too, to prevent OOM attack
					if cr.NumRoundChanges() == 0 {
						c.rounds.Remove(elem)
					}
				}
			}
		}

		// locate to round m.Round.
		// NOTE: getRound must not be called before previous checks done
		// in order to prevent OOM attack by creating round objects.
		round := c.getRound(m.Round, false)
		// as we cleared all lower rounds message, we handle the message
		// at round m.Round. if this message is not duplicated in m.Round,
		// round records message along with its signed <roundchange> message
		// to provide proofs in the future.
		if round.AddRoundChange(signed, m) {
			if global.StatusLogin == global.BureauStatus {
				//对于顶级节点，首次传播的是区块包，后面传播的是hash
				if _, ok := global.MapBlocksData[c.latestHeight+1]; !ok {
					global.MapBlocksData[c.latestHeight+1] = m.State
					m.State = global.HashBlockData(m.State)
					c.sendTo(m, c.roundLeader(m.Round))
				}
			}
			if global.StatusLogin == global.TrainStatus {
				//二级共识一个区块，后面传播的是hash
				if _, ok := global.MapBlockData[c.latestHeight+1]; !ok {
					global.MapBlockData[c.latestHeight+1] = m.State
					m.State = global.HashBlockData(m.State)
					c.sendTo(m, c.roundLeader(m.Round))
				}
			}
			// During any time of the protocol, if a the Pacemaker of Pj (including Pi)
			// receives at least 2t + 1 round-change message (including round-change
			// message from himself) for round r (which is larger than its current round
			// status), it enters lock status of round r
			//
			// NOTE: m.Round lower than currentRound.RoundNumber has been tested by
			// verifyRoundChangeMessage
			// NOTE: lock stage can only be entered once for a single round, malicious
			// participant can keep on broadcasting increasing <roundchange> to everyone,
			// and old <roundchange> messages will be removed from previous rounds in such
			// case, so rounds may possibly satisify 2*t+1 more than once.
			//
			// Example: P sends r+1 to remove from r, and sends to r again to trigger 2t+1 once
			// more to reset timeout.
			if round.NumRoundChanges() == 2*c.t()+1 && round.Stage < stageLock {
				// switch to this round
				c.switchRound(m.Round)
				// record this round change proof for resyncing
				c.lastRoundChangeProof = c.currentRound.SignedRoundChanges()

				// If Pj has not broadcasted the round-change message yet,
				// it broadcasts now.
				c.broadcastRoundChange()

				// leader of this round MUST wait on collectDuration,
				// to decide to broadcast <lock> or <select>.
				leaderKey := c.roundLeader(m.Round)
				if leaderKey == c.identity {
					// leader's <roundchange> collection timeout
					c.lockTimeout = now.Add(c.collectDuration(m.Round))
				} else {
					// non-leader's lockTimeout
					c.lockTimeout = now.Add(c.lockDuration(m.Round))
				}
				// set stage
				c.currentRound.Stage = stageLock

			}
			// for the leader, whose current round has at least 2*t+1 <roundchange>,
			// we will track max proposed state for each valid added <roundchange>
			if round == c.currentRound && round.NumRoundChanges() >= 2*c.t()+1 {
				leaderKey := c.roundLeader(m.Round)
				if leaderKey == c.identity {
					round.MaxProposedState, round.MaxProposedCount = round.GetMaxProposed()
				}
			}
		}

	case MessageType_Select:
		// verify <select> message
		err := c.verifySelectMessage(m, signed)
		if err != nil {
			return err
		}

		// round will be increased monotonically
		if m.Round > c.currentRound.RoundNumber {
			c.switchRound(m.Round)
			c.lastRoundChangeProof = []*SignedProto{signed} // record this proof for resyncing
		}

		// for rounds r' >= r, we must check c.stage to stageLockRelease
		// only once to prevent resetting lockReleaseTimeout or shifting c.cstage
		if c.currentRound.Stage < stageLockRelease {
			c.currentRound.Stage = stageLockRelease
			c.lockReleaseTimeout = now.Add(c.commitDuration(m.Round))
			c.lockRelease()
			// add to Blockj
			c.Propose(m.State)
		}

	case MessageType_Lock:
		// verify <lock> message
		err := c.verifyLockMessage(m, signed)
		if err != nil {
			return err
		}

		// round will be increased monotonically
		if m.Round > c.currentRound.RoundNumber {
			c.switchRound(m.Round)
			c.lastRoundChangeProof = []*SignedProto{signed} // record this proof for resyncing
		}

		// for rounds r' >= r, we must check to enter commit status
		// only once to prevent resetting commitTimeout or shifting c.cstage
		if c.currentRound.Stage < stageCommit {
			c.currentRound.Stage = stageCommit
			c.commitTimeout = now.Add(c.commitDuration(m.Round))

			mHash := c.stateHash(m.State)
			// release any potential lock on B' in this round
			// in-place deletion
			o := 0
			for i := 0; i < len(c.locks); i++ {
				if c.locks[i].StateHash != mHash {
					c.locks[o] = c.locks[i]
					o++ // o is the new length of c.locks
				}
			}
			c.locks = c.locks[:o]
			// append the new element
			c.locks = append(c.locks, messageTuple{StateHash: mHash, Message: m, Signed: signed})
		}

		// for any incoming <lock,h,r,B'> message with r=r', sendCommit will send
		// <commit,h,r',B'> once.
		c.sendCommit(m)

	case MessageType_LockRelease:
		// verifies the LockRelease field in message.
		lockmsg, err := c.verifyLockReleaseMessage(m.LockRelease)
		if err != nil {
			return err
		}

		// length of locks is 0, append and return.
		if len(c.locks) == 0 {
			c.locks = append(c.locks, messageTuple{StateHash: c.stateHash(lockmsg.State), Message: lockmsg, Signed: m.LockRelease})
			return nil
		}

		// remove any locks if lockmsg.r > r' and keep lockmsg.r,
		o := 0
		for i := 0; i < len(c.locks); i++ {
			if !(lockmsg.Round > c.locks[i].Message.Round) {
				// if the round of this lock is not larger than what we
				// have kept, ignore and continue.
				c.locks[o] = c.locks[i]
				o++
			}
		}

		// some locks have been removed if o is smaller than original locks length,
		// then we keep this lock.
		if o < len(c.locks) {
			c.locks = c.locks[:o]
			c.locks = append(c.locks, messageTuple{StateHash: c.stateHash(lockmsg.State), Message: lockmsg, Signed: m.LockRelease})
		}

	case MessageType_Commit:
		// leader process commits message from all participants,
		// check to see if I'm the leader of this round to process this message.
		leaderKey := c.roundLeader(m.Round)
		if leaderKey == c.identity {
			// verify commit message.
			// NOTE: leader only accept commits for current height & round.
			err := c.verifyCommitMessage(m)
			if err != nil {
				return err
			}

			// verifyCommitMessage can guarantee that the message is to currentRound,
			// so we're safe to process in current round.
			if c.currentRound.AddCommit(signed, m) {
				// NOTE: we proceed the following only when AddCommit returns true.
				// NumCommitted will only return commits with locked B'
				// and ignore non-B' commits.
				if c.currentRound.NumCommitted() >= 2*c.t()+1 {
					/*
						log.Println("======= LEADER'S DECIDE=====")
						log.Println("Height:", c.currentHeight+1)
						log.Println("Round:", c.currentRound.RoundNumber)
						log.Println("State:", State(c.currentRound.LockedState).hash())
					*/
					// broadcast decide will return what it has sent
					if global.StatusLogin == global.TrainStatus {
						//如果当前节点非一级节点，那么它需要向上级节点请求共识
						if _, ok := global.MapBlockData[c.latestHeight+1]; !ok {
							global.MyError(fmt.Errorf("二级缺少区块！！！"))
						} else {
							block := global.MapBlockData[c.latestHeight+1]
							delete(global.MapBlockData, c.latestHeight+1)
							go c.sendToSuperior(block)
						}
					}
					c.latestProof = c.broadcastDecide()
					c.heightSync(c.latestHeight+1, c.currentRound.RoundNumber, c.currentRound.LockedState, now)
					// leader should wait for 1 more latency
					c.rcTimeout = now.Add(c.roundchangeDuration(0) + c.latency)
					// broadcast <roundchange> at new height
					c.broadcastRoundChange()
				}
			}
		}

	case MessageType_Decide:
		err := c.verifyDecideMessage(m, signed)
		if err != nil {
			return err
		}

		// record this proof for chaining
		c.latestProof = signed

		// propagate this <decide> message to my neighbour.
		// NOTE: verifyDecideMessage() can stop broadcast storm.
		c.propagate(bts)
		// passive confirmation from the leader.
		c.heightSync(m.Height, m.Round, m.State, now)
		// non-leader starts waiting for rcTimeout
		c.rcTimeout = now.Add(c.roundchangeDuration(0))
		// we sync our height and broadcast new <roundchange>.
		c.broadcastRoundChange()

	case MessageType_Resync:
		// push the proofs in loopback device
		for k := range m.Proof {
			// protobuf marshalling
			out, err := proto.Marshal(m.Proof[k])
			if err != nil {
				panic(err)
			}
			c.loopback = append(c.loopback, out)
		}

	default:
		return ErrMessageUnknownMessageType
	}
	return nil
}

// Update will process timing event for the state machine, callers
// from outside MUST call this function periodically(like 20ms).
func (c *Consensus) Update(now time.Time) error {
	// as in ReceiveMessage, we also need to handle broadcasting messages
	// directed to myself.
	defer func() {
		for len(c.loopback) > 0 {
			bts := c.loopback[0]
			c.loopback = c.loopback[1:]
			_ = c.receiveMessage(bts, now)
		}
	}()
	//fmt.Println("update", len(c.peers))
	// stage switch
	switch c.currentRound.Stage {
	case stageRoundChanging:
		leaderKey := c.roundLeader(c.currentRound.RoundNumber)
		if global.StatusLogin == global.BureauStatus {
			global.RWMutexBlock.RLock()
			lengthBlocks := len(global.Blocks.Blocks)
			global.RWMutexBlock.RUnlock()
			if lengthBlocks > 0 {
				//首先判断该账户是否是Leader
				if leaderKey != c.identity {
					//将待共识区块信息发送至一级leader
					//将共识信息池内的消息发送至Leader
					var m Message
					m.Type = MessageType_BlocksInfo
					m.Height = c.latestHeight
					m.Round = c.currentRound.RoundNumber
					m.State = global.SerializeBlocks()
					c.sendTo(&m, c.roundLeader(m.Round))
					return nil
				} else {
					if len(c.unconfirmed) == 0 {
						bts := global.SerializeBlocks()
						//一级共识多个区块
						c.Propose(bts)
					}
				}
			}
		} else {
			global.RWMutexConsensusPool.RLock()
			lengthPool := 0
			if global.ConsensusInfoPool != nil {
				lengthPool = len(global.ConsensusInfoPool.Infos)
			}
			global.RWMutexConsensusPool.RUnlock()
			if lengthPool > 0 {
				if leaderKey != c.identity {
					fmt.Println("即将发送至Leader...")
					//将共识信息池内的消息发送至Leader
					var m Message
					m.Type = MessageType_ConsensusInfo
					m.Height = c.latestHeight
					m.Round = c.currentRound.RoundNumber
					m.State = global.SerializeBlockInfos()
					c.sendTo(&m, c.roundLeader(m.Round))
					return nil
				} else {
					if len(c.unconfirmed) == 0 {
						fmt.Println("即将开始共识...")
						//获取数据信息
						bts := global.SerializeBlockData()
						//二级节点首次共识传播一个区块
						c.Propose(bts)
					}
				}
			}
		}

		//fmt.Println("stageRoundChanging")
		if c.rcTimeout.IsZero() {
			panic("roundchanging stage entered, but lockTimeout not set")
		}

		if now.After(c.rcTimeout) {
			c.broadcastRoundChange()
			c.broadcastResync() // we also need to broadcast the round change event message if there is any
			c.rcTimeout = now.Add(c.roundchangeDuration(c.currentRound.RoundNumber))
		}
	case stageLock:
		if c.lockTimeout.IsZero() {
			panic("lock stage entered, but lockTimeout not set")
		}
		// leader's collection, we perform periodically check for <lock> or <select>
		// check to see if I'm the leader of this round to perform collect timeout
		leaderKey := c.roundLeader(c.currentRound.RoundNumber)
		if leaderKey == c.identity {
			// check if we have enough 2t+1 <roundchange> to lock B',
			// which B' != NULL
			if c.currentRound.MaxProposedCount >= 2*c.t()+1 {
				// lock B' to c.currentRound
				c.currentRound.LockedState = c.currentRound.MaxProposedState
				// and computes its hash for comparing B' in <commit> message
				c.currentRound.LockedStateHash = c.stateHash(c.currentRound.MaxProposedState)
				// broadcast this <lock>, leader itself will receive this message too.
				c.broadcastLock()
				// enter commit stage
				c.currentRound.Stage = stageCommit
				c.commitTimeout = now.Add(c.commitDuration(c.currentRound.RoundNumber) + c.latency)
				return nil

			} else if c.currentRound.NumRoundChanges() == len(c.participants) || now.After(c.lockTimeout) {
				// while collect timeout or all round changes have received,
				// we should try broadcast <select> message to participants.
				// enqueue all received non-NULL data
				states := c.currentRound.RoundChangeStates()
				for k := range states {
					c.Propose(states[k])
				}
				// broadcast this <select>, leader itself will receive this message too.
				c.broadcastSelect()
				// enter lock-release stage
				c.currentRound.Stage = stageLockRelease
				c.lockReleaseTimeout = now.Add(c.lockReleaseDuration(c.currentRound.RoundNumber) + c.latency)
				c.lockRelease()
				return nil
			}
		} else if now.After(c.lockTimeout) {
			// non-leader's lock timeout, enters commit status and set timeout
			c.currentRound.Stage = stageCommit
			c.commitTimeout = now.Add(c.commitDuration(c.currentRound.RoundNumber))
		}

	case stageCommit:
		if c.commitTimeout.IsZero() {
			panic("commit stage entered, but commitTimout not set")
		}

		if now.After(c.commitTimeout) {
			c.currentRound.Stage = stageLockRelease
			c.lockReleaseTimeout = now.Add(c.lockReleaseDuration(c.currentRound.RoundNumber))
			c.lockRelease()
		}
	case stageLockRelease:
		if c.lockReleaseTimeout.IsZero() {
			panic("lockRelease stage entered, but lockReleaseTimout not set")
		}
		if now.After(c.lockReleaseTimeout) {
			c.currentRound.Stage = stageRoundChanging
			// move to round +1 when lock release has timeout
			c.switchRound(c.currentRound.RoundNumber + 1)
			c.broadcastRoundChange()
			c.rcTimeout = now.Add(c.roundchangeDuration(c.currentRound.RoundNumber))
		}
	}
	return nil
}

// CurrentState returns current state along with current height & round,
// It's caller's responsibility to check if ReceiveMessage() has
// created a new height.
func (c *Consensus) CurrentState() (height uint64, round uint64, data State) {
	return c.latestHeight, c.latestRound, c.latestState
}

// CurrentProof returns current <decide> message for current height
func (c *Consensus) CurrentProof() *SignedProto { return c.latestProof }

// SetLatency sets participants expected latency for consensus core
func (c *Consensus) SetLatency(latency time.Duration) { c.latency = latency }

// HasProposed checks whether some state has been proposed via <roundchange>
// <lock> or left in c.unconfirmed
func (c *Consensus) HasProposed(state State) bool {
	stateHash := c.stateHash(state)
	for elem := c.rounds.Front(); elem != nil; elem = elem.Next() {
		cr := elem.Value.(*consensusRound)
		for k := range cr.roundChanges {
			if cr.roundChanges[k].StateHash == stateHash {
				return true
			}
		}
	}

	for k := range c.locks {
		if c.locks[k].StateHash == stateHash {
			return true
		}
	}

	for k := range c.unconfirmed {
		if c.stateHash(c.unconfirmed[k]) == stateHash {
			return true
		}
	}
	return false
}
func (c *Consensus) AddSendToSuperior(f func(bts []byte)) bool {
	if c.sendToSuperior == nil {
		c.sendToSuperior = f
		return true
	}
	return false
}
func (c *Consensus) AddSendToSubordinates(f func(bts []byte)) bool {
	if c.sendToSubordinates == nil {
		c.sendToSubordinates = f
		return true
	}
	return false
}

// Join adds a peer to consensus for message delivery, a peer is
// identified by its address.
func (c *Consensus) Join(p PeerInterface) bool {
	for k := range c.peers {
		if p.RemoteAddr().String() == c.peers[k].RemoteAddr().String() {
			return false
		}
	}
	c.peers = append(c.peers, p)
	return true
}

// Leave removes a peer from consensus, identified by its address
func (c *Consensus) Leave(addr net.Addr) bool {
	for k := range c.peers {
		if addr.String() == c.peers[k].RemoteAddr().String() {
			copy(c.peers[k:], c.peers[k+1:])
			c.peers = c.peers[:len(c.peers)-1]
			return true
		}
	}
	return false
}
