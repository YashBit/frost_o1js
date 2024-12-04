import { Bytes, Hash, Field, Group, Scalar, PublicKey } from 'o1js';

type Result<T> =
  | {
      ok: T;
      err?: string;
    }
  | {
      ok?: undefined;
      err: string;
    };

class Bytes106 extends Bytes(106) {}

class Share {
  generatorIndex: Field;
  receiverIndex: Field;
  value: Scalar;

  constructor() {
    this.generatorIndex = Field(0);
    this.receiverIndex = Field(0);
    this.value = Scalar.from(0);
  }
}

class SharesCommitment {
  commitment: Group[];

  constructor() {
    this.commitment = [];
  }
}

class KeyPair {
  index: Field;
  secret: Scalar;
  public: Group;
  group_public: Group;
}

class KeyGenSignature {
  r: Group;
  z: Scalar;

  constructor() {
    this.r = Group.generator;
    this.z = Scalar.from(0);
  }
}

class KeyGenDKGProposedCommitment {
  index: Field;
  sharesCommitment: SharesCommitment;
  zkp: KeyGenSignature;

  constructor() {
    this.index = Field(0);
    this.sharesCommitment = new SharesCommitment();
    this.zkp = new KeyGenSignature();
  }

  getCommitmentToSecret(): Group {
    return this.sharesCommitment.commitment[0];
  }
}

interface GenerateSharesResult {
  sharesCommitment: SharesCommitment;
  shares: Share[];
}

function generateShares(
  secret: Scalar,
  numShares: Field,
  threshold: Field,
  generatorIndex: Field
): Result<GenerateSharesResult> {
  try {
    // Validate inputs
    if (threshold.lessThan(1)) {
      return { err: 'Threshold cannot be 0' };
    }
    if (numShares.lessThan(1)) {
      return { err: 'Number of shares cannot be 0' };
    }
    if (threshold.greaterThan(numShares)) {
      return { err: 'Threshold cannot exceed numshares' };
    }

    const numCoeffs = threshold.sub(1);

    const coefficients: Scalar[] = [];
    for (let i = 0; i < numCoeffs.toBigInt(); i++) {
      coefficients.push(Scalar.random());
    }

    const commitment: Group[] = [];
    commitment.push(Group.generator.scale(secret));

    for (const coeff of coefficients) {
      commitment.push(Group.generator.scale(coeff));
    }

    const shares: Share[] = [];
    for (let i = 1; i <= numShares.toBigInt(); i++) {
      let scalarIndex = Scalar.from(i);
      let value = Scalar.from(0);

      for (let j = numCoeffs.toBigInt() - 1n; j >= 0; j--) {
        value = value.add(coefficients[Number(j)]);
        value = value.mul(scalarIndex);
      }

      value = value.add(secret);

      const share = new Share();
      share.generatorIndex = generatorIndex;
      share.receiverIndex = Field.from(i);
      share.value = value;
      shares.push(share);
    }
    const sharesCommitment = new SharesCommitment();
    sharesCommitment.commitment = commitment;

    return {
      ok: {
        sharesCommitment,
        shares,
      },
    };
  } catch (error) {
    return {
      err: `Error generating shares: ${error instanceof Error ? error.message : 'unknown error'}`,
    };
  }
}

function verify_share(
  threshold: Field,
  share: Share,
  commitment: SharesCommitment
): Result<void> {
  try {
    // Calculate f(x) = g^share
    const f_result = Group.generator.scale(share.value);
    const term = Scalar.from(share.receiverIndex.toBigInt());
    let result = new Group({ x: Field(0), y: Field(1) });
    if (BigInt(commitment.commitment.length) !== threshold.toBigInt()) {
      return { err: 'Commitment is invalid.' };
    }
    for (let i = commitment.commitment.length - 1; i >= 0; i--) {
      result = result.add(commitment.commitment[i]);
      if (i !== 0) {
        result = result.scale(term);
      }
    }
    if (!f_result.equals(result)) {
      return { err: 'Share is invalid.' };
    }
    return { ok: undefined };
  } catch (error) {
    return {
      err: `Error verifying share: ${error instanceof Error ? error.message : 'unknown error'}`,
    };
  }
}

function isValidZKP(
  challenge: Scalar,
  comm: KeyGenDKGProposedCommitment
): Result<void> {
  try {
    const basePointScaled = Group.generator.scale(comm.zkp.z);
    const commitmentScaled = comm.getCommitmentToSecret().scale(challenge);
    const difference = basePointScaled.sub(commitmentScaled);

    if (!comm.zkp.r.equals(difference)) {
      return { err: 'Signature is invalid' };
    }

    return { ok: undefined };
  } catch (error) {
    return {
      err: `Error validating ZKP: ${error instanceof Error ? error.message : 'unknown error'}`,
    };
  }
}

function generateDKGChallenge(
  index: Field,
  context: string,
  publicKey: Group,
  commitment: Group
): Result<Scalar> {
  try {
    const commitmentHex = commitment
      .toFields()
      .map((f) => f.toBigInt().toString(16))
      .join('');
    const publicKeyHex = publicKey
      .toFields()
      .map((f) => f.toBigInt().toString(16))
      .join('');

    const indexHex = index.toBigInt().toString(16);
    const contextHex = Buffer.from(context).toString('hex');
    // Combine for Challenge Creation
    const combinedHex =
      commitmentHex.padStart(64, '0') +
      publicKeyHex.padStart(64, '0') +
      indexHex.padStart(20, '0') +
      contextHex.padStart(64, '0');
    const bytes = Bytes106.fromHex(combinedHex);
    // SHA-256 in o1js
    const shaHash = Hash.SHA3_256.hash(bytes);
    const scalar = Scalar.fromFields(shaHash.toFields());
    return { ok: scalar };
  } catch (error) {
    return {
      err: `Error generating DKG challenge: ${error instanceof Error ? error.message : 'unknown error'}`,
    };
  }
}

class KeyGenDKGCommitment {
  index: Field;
  sharesCommitment: SharesCommitment;

  constructor() {
    this.index = Field(0);
    this.sharesCommitment = new SharesCommitment();
  }
}

interface KeyGenBeginResult {
  commitment: KeyGenDKGProposedCommitment;
  shares: Share[];
}

interface KeyGenValidateResult {
  invalidPeerIds: Field[];
  validCommitments: KeyGenDKGCommitment[];
}

function keyGenBegin(
  numshares: Field,
  threshold: Field,
  generatorIndex: Field,
  context: string
): Result<KeyGenBeginResult> {
  try {
    // Generate random secret
    const secret = Scalar.random();

    // Generate shares for the secret
    const sharesResult = generateShares(
      secret,
      numshares,
      threshold,
      generatorIndex
    );
    if (sharesResult.err) return { err: sharesResult.err };

    // Ensure shares were generated successfully
    if (!sharesResult.ok) {
      return { err: 'Share generation failed' };
    }

    // Generate random nonce for ZKP
    const r = Scalar.random();
    const rPub = Group.generator.scale(r);
    const sPub = Group.generator.scale(secret);

    // Generate challenge for ZKP
    const challengeResult = generateDKGChallenge(
      generatorIndex,
      context,
      sPub,
      rPub
    );
    if (challengeResult.err) return { err: challengeResult.err };

    const challenge = challengeResult.ok;
    if (!challenge) {
      return { err: 'Challenge generation failed' };
    }

    // Calculate ZKP with guaranteed Scalar type
    const z = r.add(secret.mul(challenge));

    // Create commitment using verified shares result
    const dkgCommitment = new KeyGenDKGProposedCommitment();
    dkgCommitment.index = generatorIndex;
    dkgCommitment.sharesCommitment = sharesResult.ok.sharesCommitment;
    dkgCommitment.zkp = { r: rPub, z };

    return {
      ok: {
        commitment: dkgCommitment,
        shares: sharesResult.ok.shares,
      },
    };
  } catch (error) {
    return {
      err: `Error in keyGenBegin: ${error instanceof Error ? error.message : 'unknown error'}`,
    };
  }
}

function keygenReceiveCommitmentsAndValidatePeers(
  peerCommitments: KeyGenDKGProposedCommitment[],
  context: string
): Result<KeyGenValidateResult> {
  try {
    const invalidPeerIds: Field[] = [];
    const validCommitments: KeyGenDKGCommitment[] = [];

    for (const commitment of peerCommitments) {
      // Generate challenge for verification
      const challengeResult = generateDKGChallenge(
        commitment.index,
        context,
        commitment.getCommitmentToSecret(),
        commitment.zkp.r
      );

      if (challengeResult.err) return { err: challengeResult.err };
      const challenge = challengeResult.ok;
      if (!challenge) {
        return { err: 'Challenge generation failed' };
      }
      const zkpResult = isValidZKP(challenge, commitment);

      if (zkpResult.err) {
        invalidPeerIds.push(commitment.index);
      } else {
        const validCommitment = new KeyGenDKGCommitment();
        validCommitment.index = commitment.index;
        validCommitment.sharesCommitment = commitment.sharesCommitment;
        validCommitments.push(validCommitment);
      }
    }

    return {
      ok: {
        invalidPeerIds,
        validCommitments,
      },
    };
  } catch (error) {
    return {
      err: `Error in keygenReceiveCommitmentsAndValidatePeers: ${
        error instanceof Error ? error.message : 'unknown error'
      }`,
    };
  }
}

function keygenFinalize(
  index: Field,
  threshold: Field,
  shares: Share[],
  commitments: KeyGenDKGCommitment[]
): Result<KeyPair> {
  try {
    for (const share of shares) {
      const matchingCommitment = commitments.find(
        (comm) => comm.index.toString() === share.generatorIndex.toString()
      );

      if (!matchingCommitment) {
        return { err: 'Received share with no corresponding commitment' };
      }

      const verifyResult = verify_share(
        threshold,
        share,
        matchingCommitment.sharesCommitment
      );
      if (verifyResult.err) return { err: verifyResult.err };
    }
    let secret = Scalar.from(0);
    for (const share of shares) {
      secret = secret.add(share.value);
    }
    const public_key = Group.generator.scale(secret);
    let group_public = new Group({ x: Field(0), y: Field(1) }); // Identity point
    for (const comm of commitments) {
      group_public = group_public.add(comm.sharesCommitment.commitment[0]);
    }

    return {
      ok: {
        index,
        secret,
        public: public_key,
        group_public,
      },
    };
  } catch (error) {
    return {
      err: `Error in keygenFinalize: ${error instanceof Error ? error.message : 'unknown error'}`,
    };
  }
}
