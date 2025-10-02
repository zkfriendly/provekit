use {
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::Field,
    provekit_common::{
        witness::{ConstantOrR1CSWitness, SumTerm, WitnessBuilder},
        FieldElement,
    },
};

/// Poseidon2 permutation for BN254 with state width t=4
/// Based on the Poseidon2 specification: https://eprint.iacr.org/2023/323.pdf

// Number of full rounds for Poseidon2 with t=4 on BN254
const ROUNDS_F: usize = 8;

// Number of partial rounds for Poseidon2 with t=4 on BN254  
const ROUNDS_P: usize = 56;

// Total rounds  
const TOTAL_ROUNDS: usize = ROUNDS_F + ROUNDS_P; // 64

// Poseidon2 round constants for BN254 with t=4
// These are generated using the standard Poseidon2 parameter generation process
const ROUND_CONSTANTS: [[&str; 4]; TOTAL_ROUNDS] = [
    // External rounds (first half)
    [
        "14397397413755236225575615486459253198602422701513067526754101844196324375522",
        "10405129301473404666785234951972711717481302463898292859783056520670200613128",
        "5646423851688744596075298356341839697077728656077334684139524882710359528089",
        "12867689367012286679447239959248989907151217152056302943638703334088732754313"
    ],
    [
        "10816790825593568710055091653825093373463235452930326604133867430375330866904",
        "11321889219665768653752190906718089015361773622121703111040018885193278217420",
        "4073698157273821139085601403098704990541530602734810999995009585572883651672",
        "8046551909849103034348917551206606855254962854427421740846619113630866519189"
    ],
    [
        "11682200980175004774702035349368849132739250570402204677568825603938003099946",
        "21398498033469973333738753442912153925421243810430226925049345774126206411820",
        "15357660719588787046558848284067172115672553383609792031770090052867059958105",
        "9624623836199395652437086712932482914907423821666933653127482028925868268696"
    ],
    [
        "13430372800738231219919155323990367565158450990312095038937907234623782330908",
        "18639235793932729893813952328787329287626789166149951420833922468942484672222",
        "11988183006337187254798925852918058859895174827951712661042167803931063058934",
        "21588804914056167058997518859318413970113932597814918916341934076848148699764"
    ],
    // Partial rounds
    [
        "9604479263524503855414374642705332668789164866866863896196221863928088229647",
        "0",
        "0", 
        "0"
    ],
    [
        "517881963422817258014306639119401512660637144621331050934508615685056833082",
        "0",
        "0",
        "0"
    ],
    [
        "6074047913811771820930810571087479833837165947739541089729606268102670963752",
        "0",
        "0",
        "0"
    ],
    [
        "18936818173480011669507163011118288089468827259971823710084042637943169905422",
        "0",
        "0",
        "0"
    ],
    [
        "16640234279732888028151893653166128482354281642424991683201165556169296086629",
        "0",
        "0",
        "0"
    ],
    [
        "12767309895790213341204423166133394743878564121513555589098062922815960699936",
        "0",
        "0",
        "0"
    ],
    [
        "19702561053141677990150052333689670636046940770659743788337925893639474712936",
        "0",
        "0",
        "0"
    ],
    [
        "21687361941551468839969058674446882201415471979031697929831916808820759530637",
        "0",
        "0",
        "0"
    ],
    [
        "19591133112198913879775433009061766054620341405225925997878880230814693588081",
        "0",
        "0",
        "0"
    ],
    [
        "21710585864159376866686366000249969144615644456874923796735025852438655947903",
        "0",
        "0",
        "0"
    ],
    [
        "12789104779678410965304064355164712783965988433460675917711136718819046043051",
        "0",
        "0",
        "0"
    ],
    [
        "20682556379821420084828365566598651041193725040822646347786942383097676112810",
        "0",
        "0",
        "0"
    ],
    [
        "13145383999634757495014055909688164110359789866056309546373302591673605796796",
        "0",
        "0",
        "0"
    ],
    [
        "8562045850261682122838164528527959814749436649267803502022094097766226158009",
        "0",
        "0",
        "0"
    ],
    [
        "5969373094369877794543896879809695224779690699932092092409460041991661005098",
        "0",
        "0",
        "0"
    ],
    [
        "7047081409653397068219316671603348372413128943087524438906340863436168885844",
        "0",
        "0",
        "0"
    ],
    [
        "4076178207285207663452503093769861177802614752614854801680978375871896008677",
        "0",
        "0",
        "0"
    ],
    [
        "12661821769493692691629787394098532789196590424152283145806625849666449048723",
        "0",
        "0",
        "0"
    ],
    [
        "15820220975583997798651127103035631851002447163398693398274509301977553916093",
        "0",
        "0",
        "0"
    ],
    [
        "15953091258922197767637925938824869114820125243222481030482239854438360667048",
        "0",
        "0",
        "0"
    ],
    [
        "4344857843853316319601976281910277863184837506044915127093104952054793888742",
        "0",
        "0",
        "0"
    ],
    [
        "1000960476843799343404303882436663557093815476814420348062751695330162084093",
        "0",
        "0",
        "0"
    ],
    [
        "2343278761090398552513174091876421922176066949290018636932474343797042092435",
        "0",
        "0",
        "0"
    ],
    [
        "20537731460412933643966898421422061043283660992765372651112883883176095087801",
        "0",
        "0",
        "0"
    ],
    [
        "5779464378652998195611159727155176268614895207453345760979614639931522671823",
        "0",
        "0",
        "0"
    ],
    [
        "15403991267317698971907934321043918447611652030009039682103630433959066528151",
        "0",
        "0",
        "0"
    ],
    [
        "14624065346458469061856159092370645292333506803241162230641816838256049976888",
        "0",
        "0",
        "0"
    ],
    [
        "3436639758942412883954789044203654472730775667698084434916129341307369085524",
        "0",
        "0",
        "0"
    ],
    [
        "10059923219175558128292873046946840346363521359611842891869988763369567168146",
        "0",
        "0",
        "0"
    ],
    [
        "10141398057562975854711484986929905169914330979050938312478022421842408891071",
        "0",
        "0",
        "0"
    ],
    [
        "11509887653349959098735994274921958439739893236813261044442974095821091307049",
        "0",
        "0",
        "0"
    ],
    [
        "10987477949627125638892170589739581802526098789133606925193695988905804564863",
        "0",
        "0",
        "0"
    ],
    [
        "3824172595479750693651984738758027414498923090259415668813913864175113872026",
        "0",
        "0",
        "0"
    ],
    [
        "17762308048886122797071373000043250820203055435305619513554838596876090170906",
        "0",
        "0",
        "0"
    ],
    [
        "21213966097226750123448103674027768531922009871064569564958917719327024088913",
        "0",
        "0",
        "0"
    ],
    [
        "18098992126856699166366606608734997170694047623400346056033943389473758629654",
        "0",
        "0",
        "0"
    ],
    [
        "9050064357635597166166453585707037996758043926815691050486086945846944528795",
        "0",
        "0",
        "0"
    ],
    [
        "17562478896840238226777081752170668735450472140183922598075064094456041256854",
        "0",
        "0",
        "0"
    ],
    [
        "13454546872893304433935048174551095095756289314107430923231967960796506827156",
        "0",
        "0",
        "0"
    ],
    [
        "1630438563565347383092573009916079625775264058826858869675451212498634359171",
        "0",
        "0",
        "0"
    ],
    [
        "3037746916814006663806809071060328723020632272148053832662002809061153742050",
        "0",
        "0",
        "0"
    ],
    [
        "17976170012387653102611510871810679903584279939799925302750929377168089835863",
        "0",
        "0",
        "0"
    ],
    [
        "19263099252345002562125865512890054042654906872943242346171850014808952799872",
        "0",
        "0",
        "0"
    ],
    [
        "15530851493831509815022164053348103429046422088856394498160849123706006031422",
        "0",
        "0",
        "0"
    ],
    [
        "18039447269533502729359982618050819300069797221650307669453628803791679329433",
        "0",
        "0",
        "0"
    ],
    [
        "8624817275735648436264050736868956406616467885933000098619250924767531201948",
        "0",
        "0",
        "0"
    ],
    [
        "12890834147864446099858011066675988055477418691463649527785948072730695960387",
        "0",
        "0",
        "0"
    ],
    [
        "16356431485969606386175755597867681473645043282787736933337698606785296381967",
        "0",
        "0",
        "0"
    ],
    [
        "2306016181503650089850382898116942026616327054253838194713066552528484358558",
        "0",
        "0",
        "0"
    ],
    [
        "8172572037683715858326380246035890762114931173798061961913061693372041453460",
        "0",
        "0",
        "0"
    ],
    [
        "9928991897153273541195290143823258341094125890953197181963181054652929948356",
        "0",
        "0",
        "0"
    ],
    [
        "16698176838355198867748912025857270403732709176527287851645853916678803134942",
        "0",
        "0",
        "0"
    ],
    [
        "21437368142961670006406089719923074549639195403328052025734844318411936974846",
        "0",
        "0",
        "0"
    ],
    [
        "18052503329413042877817802181661700042312293036488858735407265348035056554729",
        "0",
        "0",
        "0"
    ],
    [
        "21154989925053303181116046616649659856360879821100275606092994988738798124912",
        "0",
        "0",
        "0"
    ],
    [
        "10342643167760699094430849677725782821975682562530002312682797570286663755813",
        "0",
        "0",
        "0"
    ],
    // External rounds (second half)
    [
        "20553701507984878242811603665249555106498906382149302458310942228091823489898",
        "19451030222905843467893124788422994066859953598839825614081842797507651673366",
        "8301887082437180744271624698284643589851966399127914321658732124278863752588",
        "4220782868768949419390804563394351635966403648903398800878474162122165696633"
    ],
    [
        "15050634696959504555437321597512848816094930852122370783900085043637092105653",
        "20725315473723830991856378664086183348129090859932849994643191362775288987130",
        "18033663960387562529813931102658747854742283074738653307735641323850493273053",
        "13888908098853270113726132092734802288610698678863256074349838986272508299906"
    ],
    [
        "15839323138007732449112803088135827576945413013000489549863196453662098273042",
        "5165011271166670315855154690054377647828413086044149026486220883531002883788",
        "6865320607698976943080528606306222169717690702726629069356590673079949126562",
        "21401807621125923341064698340813846012903577988893625788698732334351212177399"
    ],
    [
        "16401781125990277317899743124815673555370073074077975056310926359305849318063",
        "10034388912758846299330095756682883306603419255872739321074991787088144565016",
        "15729363764697090050988619549116684619561042878750847750182692509650612604910",
        "10988754996051886036267752098603711175054056695506652933099126088697893925531"
    ],
];

// Internal diagonal matrix elements for Poseidon2  
// Diagonal matrix M_I for t=4 (using 2^64 as multiplier - simplified)
fn get_internal_matrix_diag() -> [FieldElement; 4] {
    let val = FieldElement::from(18446744069414584320u128); // 2^64
    [val, val, val, val]
}

/// Parse round constants from strings
fn parse_round_constants() -> Vec<[FieldElement; 4]> {
    ROUND_CONSTANTS.iter().map(|round| {
        [
            round[0].parse().expect("valid field element"),
            round[1].parse().expect("valid field element"),
            round[2].parse().expect("valid field element"),
            round[3].parse().expect("valid field element"),
        ]
    }).collect()
}

/// Add constraints for the S-box (x^5) operation
/// Returns the witness index for the result
fn add_sbox(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    x_witness: usize,
) -> usize {
    // Compute x^5 = x * x^2 * x^2
    // First compute x^2
    let x2_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);
    
    r1cs_compiler.witness_builders.push(WitnessBuilder::Product(
        x2_witness,
        x_witness,
        x_witness,
    ));

    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, x_witness)],
        &[(FieldElement::ONE, x_witness)],
        &[(FieldElement::ONE, x2_witness)],
    );

    // Then compute x^4 = x^2 * x^2
    let x4_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    r1cs_compiler.witness_builders.push(WitnessBuilder::Product(
        x4_witness,
        x2_witness,
        x2_witness,
    ));

    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, x2_witness)],
        &[(FieldElement::ONE, x2_witness)],
        &[(FieldElement::ONE, x4_witness)],
    );

    // Finally compute x^5 = x^4 * x
    let x5_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    r1cs_compiler.witness_builders.push(WitnessBuilder::Product(
        x5_witness,
        x4_witness,
        x_witness,
    ));

    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::ONE, x4_witness)],
        &[(FieldElement::ONE, x_witness)],
        &[(FieldElement::ONE, x5_witness)],
    );

    x5_witness
}

/// Add external round (apply S-box to all elements and mix)
fn add_external_round(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    state: [usize; 4],
    round_constants: &[FieldElement; 4],
) -> [usize; 4] {
    // Add round constants and apply S-box to all state elements
    let mut new_state = [0; 4];
    for i in 0..4 {
        // Create witness for state[i] + round_constant[i]
        let added_witness = r1cs_compiler.num_witnesses();
        r1cs_compiler.r1cs.add_witnesses(1);
        
        r1cs_compiler.witness_builders.push(WitnessBuilder::Sum(
            added_witness,
            vec![
                SumTerm(Some(FieldElement::ONE), state[i]),
                SumTerm(Some(round_constants[i]), r1cs_compiler.witness_one()),
            ]
        ));

        r1cs_compiler.r1cs.add_constraint(
            &[
                (FieldElement::ONE, state[i]),
                (round_constants[i], r1cs_compiler.witness_one()),
            ],
            &[(FieldElement::ONE, r1cs_compiler.witness_one())],
            &[(FieldElement::ONE, added_witness)],
        );

        // Apply S-box
        new_state[i] = add_sbox(r1cs_compiler, added_witness);
    }

    // Apply external linear layer (full MDS matrix multiplication)
    // For now, use a simple mixing - this should be replaced with the actual MDS matrix
    // The standard Poseidon2 external matrix for t=4
    apply_external_matrix(r1cs_compiler, new_state)
}

/// Apply the external MDS matrix
fn apply_external_matrix(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    state: [usize; 4],
) -> [usize; 4] {
    // Simplified external matrix for t=4 (circulant matrix)
    // This is a placeholder - use actual Poseidon2 matrix
    let mut new_state = [0; 4];
    
    for i in 0..4 {
        let result_witness = r1cs_compiler.num_witnesses();
        r1cs_compiler.r1cs.add_witnesses(1);

        // Simple mixing: new_state[i] = 2*state[i] + state[(i+1)%4] + state[(i+2)%4] + state[(i+3)%4]
        r1cs_compiler.witness_builders.push(WitnessBuilder::Sum(
            result_witness,
            vec![
                SumTerm(Some(FieldElement::from(2u64)), state[i]),
                SumTerm(Some(FieldElement::ONE), state[(i + 1) % 4]),
                SumTerm(Some(FieldElement::ONE), state[(i + 2) % 4]),
                SumTerm(Some(FieldElement::ONE), state[(i + 3) % 4]),
            ]
        ));

        r1cs_compiler.r1cs.add_constraint(
            &[
                (FieldElement::from(2u64), state[i]),
                (FieldElement::ONE, state[(i + 1) % 4]),
                (FieldElement::ONE, state[(i + 2) % 4]),
                (FieldElement::ONE, state[(i + 3) % 4]),
            ],
            &[(FieldElement::ONE, r1cs_compiler.witness_one())],
            &[(FieldElement::ONE, result_witness)],
        );

        new_state[i] = result_witness;
    }

    new_state
}

/// Add partial round (apply S-box only to first element and mix)
fn add_partial_round(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    state: [usize; 4],
    round_constant: FieldElement,
) -> [usize; 4] {
    let mut new_state = state;

    // Add round constant to first element and apply S-box
    let added_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.r1cs.add_witnesses(1);

    r1cs_compiler.witness_builders.push(WitnessBuilder::Sum(
        added_witness,
        vec![
            SumTerm(Some(FieldElement::ONE), state[0]),
            SumTerm(Some(round_constant), r1cs_compiler.witness_one()),
        ]
    ));

    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::ONE, state[0]),
            (round_constant, r1cs_compiler.witness_one()),
        ],
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[(FieldElement::ONE, added_witness)],
    );

    new_state[0] = add_sbox(r1cs_compiler, added_witness);

    // Apply internal linear layer (diagonal matrix)
    apply_internal_matrix(r1cs_compiler, new_state)
}

/// Apply the internal diagonal matrix
fn apply_internal_matrix(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    state: [usize; 4],
) -> [usize; 4] {
    let mut new_state = [0; 4];
    let m_i_diag = get_internal_matrix_diag();

    for i in 0..4 {
        let result_witness = r1cs_compiler.num_witnesses();
        r1cs_compiler.r1cs.add_witnesses(1);

        // Multiply by diagonal element
        r1cs_compiler.witness_builders.push(WitnessBuilder::Sum(
            result_witness,
            vec![
                SumTerm(Some(m_i_diag[i]), state[i]),
            ]
        ));

        r1cs_compiler.r1cs.add_constraint(
            &[(m_i_diag[i], state[i])],
            &[(FieldElement::ONE, r1cs_compiler.witness_one())],
            &[(FieldElement::ONE, result_witness)],
        );

        new_state[i] = result_witness;
    }

    new_state
}

/// Add Poseidon2 permutation constraints
pub(crate) fn add_poseidon2_permutation(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    poseidon2_ops: Vec<(Vec<ConstantOrR1CSWitness>, Vec<usize>, usize)>,
) {
    // Parse round constants once
    let rc = parse_round_constants();
    
    for (inputs, outputs, len) in poseidon2_ops {
        assert_eq!(len, 4, "Poseidon2 currently only supports state width 4");
        assert_eq!(inputs.len(), 4, "Expected 4 inputs for Poseidon2");
        assert_eq!(outputs.len(), 4, "Expected 4 outputs for Poseidon2");

        // Convert inputs to witness indices
        let mut state: [usize; 4] = inputs
            .iter()
            .map(|input| match input {
                ConstantOrR1CSWitness::Witness(idx) => *idx,
                ConstantOrR1CSWitness::Constant(val) => {
                    // Create a witness for the constant
                    let witness_idx = r1cs_compiler.num_witnesses();
                    r1cs_compiler.r1cs.add_witnesses(1);
                    r1cs_compiler.witness_builders.push(WitnessBuilder::Sum(
                        witness_idx,
                        vec![
                            SumTerm(Some(*val), r1cs_compiler.witness_one()),
                        ]
                    ));
                    r1cs_compiler.r1cs.add_constraint(
                        &[(*val, r1cs_compiler.witness_one())],
                        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                        &[(FieldElement::ONE, witness_idx)],
                    );
                    witness_idx
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Apply rounds
        let mut round_idx = 0;

        // First half of external rounds
        for _ in 0..(ROUNDS_F / 2) {
            state = add_external_round(r1cs_compiler, state, &rc[round_idx]);
            round_idx += 1;
        }

        // Partial rounds
        for _ in 0..ROUNDS_P {
            state = add_partial_round(r1cs_compiler, state, rc[round_idx][0]);
            round_idx += 1;
        }

        // Second half of external rounds
        for _ in 0..(ROUNDS_F / 2) {
            state = add_external_round(r1cs_compiler, state, &rc[round_idx]);
            round_idx += 1;
        }

        // Constrain outputs to equal final state
        for i in 0..4 {
            r1cs_compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, state[i])],
                &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                &[(FieldElement::ONE, outputs[i])],
            );
        }
    }
}

