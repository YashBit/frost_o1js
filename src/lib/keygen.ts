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

class SharesCommitment {}
class Share {}

function generateShares(
  secret: Scalar,
  numShares: Field,
  threshold: Field,
  generator_index: Field
): any {
  console.log('TODO');
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
