use ark_serialize::CanonicalSerialize;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use super::{Polynomial, PolynomialCommitment};

impl Serialize for Polynomial {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer
	{
		unimplemented!()
	}
}

impl Serialize for PolynomialCommitment {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer
	{
		unimplemented!()
	}
}

impl<'de> Deserialize<'de> for Polynomial {
	fn deserialize<D>(deserializer: D) -> Result<Polynomial, D::Error>
	where
		D: Deserializer<'de>
	{
		unimplemented!()
	}
}

impl<'de> Deserialize<'de> for PolynomialCommitment {
	fn deserialize<D>(deserializer: D) -> Result<PolynomialCommitment, D::Error>
	where
		D: Deserializer<'de>
	{
		unimplemented!()
	}
}