import { TestBed } from '@angular/core/testing';
import { AppComponent } from './app.component';
import { createSignerVerifier, digest, generateSalt } from './sd-jwt';
import { DisclosureFrame, SDJwtInstance } from '@hopae/sd-jwt';

describe('AppComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AppComponent],
    }).compileComponents();
  });

  it('Example', async () => {
    const { signer, verifier } = await createSignerVerifier();
    const sdjwt = new SDJwtInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'SHA-256',
      saltGenerator: generateSalt,
    });

    const claims = {
      firstname: 'John',
      lastname: 'Doe',
      ssn: '123-45-6789',
      id: '1234',
      data: {
        firstname: 'John',
        lastname: 'Doe',
        ssn: '123-45-6789',
        list: [{ r: '1' }, 'b', 'c'],
      },
      data2: {
        hi: 'bye',
      },
    };
    const disclosureFrame: DisclosureFrame<typeof claims> = {
      _sd: ['firstname', 'id', 'data2'],
      data: {
        _sd: ['list'],
        _sd_decoy: 2,
        list: {
          _sd: [0, 2],
          _sd_decoy: 1,
          0: {
            _sd: ['r'],
          },
        },
      },
      data2: {
        _sd: ['hi'],
      },
    };
    const encodedSdjwt = await sdjwt.issue(claims, disclosureFrame);
    expect(encodedSdjwt).toBeDefined();
    const validated = await sdjwt.validate(encodedSdjwt);
    expect(validated).toBeDefined();

    const decoded = await sdjwt.decode(encodedSdjwt);
    const keys = await decoded.keys(digest);
    expect(keys).toEqual([
      'data',
      'data.firstname',
      'data.lastname',
      'data.list',
      'data.list.0',
      'data.list.0.r',
      'data.list.1',
      'data.list.2',
      'data.ssn',
      'data2',
      'data2.hi',
      'firstname',
      'id',
      'lastname',
      'ssn',
    ]);
    const payloads = await decoded.getClaims(digest);
    expect(payloads).toEqual(claims);
    const presentableKeys = await decoded.presentableKeys(digest);
    expect(presentableKeys).toEqual([
      'data.list',
      'data.list.0',
      'data.list.0.r',
      'data.list.2',
      'data2',
      'data2.hi',
      'firstname',
      'id',
    ]);

    const presentationFrame = ['firstname', 'id'];
    const presentedSDJwt = await sdjwt.present(encodedSdjwt, presentationFrame);
    expect(presentedSDJwt).toBeDefined();

    const presentationClaims = await sdjwt.getClaims(presentedSDJwt);
    expect(presentationClaims).toBeDefined();
    expect(presentationClaims).toEqual({
      lastname: 'Doe',
      ssn: '123-45-6789',
      data: { firstname: 'John', lastname: 'Doe', ssn: '123-45-6789' },
      id: '1234',
      firstname: 'John',
    });

    const requiredClaimKeys = ['firstname', 'id', 'data.ssn'];
    const verified = await sdjwt.verify(encodedSdjwt, requiredClaimKeys);
    expect(verified).toBeDefined();
  });
});
