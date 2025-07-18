use {crate::poseidon, ark_bn254::Fr, ark_ff::MontFp};

// Random initial state (nothing up my sleeve: digits of 2 * pi in groups of 77
// digits)
const INITIAL_STATE: [Fr; 16] = [
    MontFp!("314159265358979323846264338327950288419716939937510582097494"),
    MontFp!("45923078164062862089986280348253421170679821480865132823066470"),
    MontFp!("93844609550582231725359408128481117450284102701938521105559644"),
    MontFp!("62294895493038196442881097566593344612847564823378678316527120"),
    MontFp!("19091456485669234603486104543266482133936072602491412737245870"),
    MontFp!("06606315588174881520920962829254091715364367892590360011330530"),
    MontFp!("54882046652138414695194151160943305727036575959195309218611738"),
    MontFp!("19326117931051185480744623799627495673518857527248912279381830"),
    MontFp!("11949129833673362440656643086021394946395224737190702179860943"),
    MontFp!("70277053921717629317675238467481846766940513200056812714526356"),
    MontFp!("08277857713427577896091736371787214684409012249534301465495853"),
    MontFp!("71050792279689258923542019956112129021960864034418159813629774"),
    MontFp!("77130996051870721134999999837297804995105973173281609631859502"),
    MontFp!("44594553469083026425223082533446850352619311881710100031378387"),
    MontFp!("52886587533208381420617177669147303598253490428755468731159562"),
    MontFp!("86388235378759375195778185778053217122680661300192787661119590"),
];

const RATE: usize = 10;
const CAPACITY: usize = 6;
const T: usize = RATE + CAPACITY;

#[derive(Debug)]
pub struct Sponge {
    state: [Fr; T],
    idx: usize,
}

impl Sponge {
    pub fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            idx: 0,
        }
    }

    pub fn absorb(&mut self, value: Fr) {
        if self.idx < RATE {
            self.state[self.idx] += value;
            self.idx += 1;
        } else {
            // Permute and reset absorb index
            poseidon::permute_16(&mut self.state);
            self.state[0] += value;
            self.idx = 1;
        }
    }

    pub fn squeeze(&mut self) -> Fr {
        if self.idx >= RATE {
            poseidon::permute_16(&mut self.state);
            self.idx = 0
        }
        let out = self.state[self.idx];
        self.idx += 1;
        out
    }
}

impl Default for Sponge {
    fn default() -> Self {
        Sponge::new()
    }
}
