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
  threshold: Group,
  share: Share,
  commitment: SharesCommitment
): any {
  console.log('TODO');
}

function isValidZKP(): any {}

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
    const combinedHex =
      commitmentHex.padStart(64, '0') +
      publicKeyHex.padStart(64, '0') +
      indexHex.padStart(20, '0') +
      contextHex.padStart(64, '0');
    const bytes = Bytes106.fromHex(combinedHex);
    const shaHash = Hash.SHA3_256.hash(bytes);
    const scalar = Scalar.fromFields(shaHash.toFields());
    return { ok: scalar };
  } catch (error) {
    return {
      err: `Error generating DKG challenge: ${error instanceof Error ? error.message : 'unknown error'}`,
    };
  }
}

function keyGenBegin(): any {}
function keygenReceiveCommitmentsAndValidatePeers(): any {}
function keygenFinalize(): any {}
