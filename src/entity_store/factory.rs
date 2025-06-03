use crate::entity_store::api::EntityStore;
use crate::entity_store::implementation::InMemoryEntityStore;

pub fn create_entity_store() -> Box<dyn EntityStore> {
    Box::new(InMemoryEntityStore::new())
}
