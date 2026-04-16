/*
 * Copyright 2026 Cybersecurity Lab, University of Udine or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use cedar_policy_core::ast::{Entity, EntityUID, PartialValue};
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};

/// A builder for [`Entity`].
#[derive(Debug, Clone)]
pub struct EntityBuilder {
    uid: EntityUID,
    attrs: HashMap<SmolStr, PartialValue>,
    indirect_ancestors: HashSet<EntityUID>,
    parents: HashSet<EntityUID>,
    tags: HashMap<SmolStr, PartialValue>,
}

impl EntityBuilder {
    /// Start a brand-new empty entity with the given UID.
    pub fn new(uid: EntityUID) -> Self {
        Self {
            uid,
            attrs: HashMap::new(),
            indirect_ancestors: HashSet::new(),
            parents: HashSet::new(),
            tags: HashMap::new(),
        }
    }

    /// Consume an existing `Entity`, extracting its data without cloning.
    pub fn from_entity(entity: Entity) -> Self {
        // into_inner(): (uid, attrs, indirect, parents, tags)
        let (uid, attrs, indirect_ancestors, parents, tags) = entity.into_inner();
        Self {
            uid,
            attrs,
            indirect_ancestors,
            parents,
            tags,
        }
    }

    /// Clone an `&Entity` once (O(n)) and reuse its data.
    pub fn from_entity_ref(entity: &Entity) -> Self {
        // entity.clone() does a full clone of maps/sets
        Self::from_entity(entity.clone())
    }

    /// Change the UID.
    pub fn uid(&mut self, uid: EntityUID) -> &mut Self {
        self.uid = uid;
        self
    }

    /// Insert or overwrite an attribute.
    pub fn add_attr(&mut self, key: impl Into<SmolStr>, val: PartialValue) -> &mut Self {
        self.attrs.insert(key.into(), val);
        self
    }

    /// Remove an attribute by name.
    pub fn remove_attr(&mut self, key: &str) -> &mut Self {
        self.attrs.remove(key);
        self
    }

    /// Insert or overwrite a collection of attributes.
    pub fn with_attrs(
        &mut self,
        attrs: impl IntoIterator<Item = (SmolStr, PartialValue)>,
    ) -> &mut Self {
        self.attrs.extend(attrs);
        self
    }

    /// Insert or overwrite a tag.
    pub fn add_tag(mut self, key: impl Into<SmolStr>, val: PartialValue) -> Self {
        self.tags.insert(key.into(), val);
        self
    }

    /// Remove a tag by name.
    pub fn remove_tag(mut self, key: &str) -> Self {
        self.tags.remove(key);
        self
    }

    /// Insert or overwrite a collection of tags.
    pub fn with_tags(
        &mut self,
        tags: impl IntoIterator<Item = (SmolStr, PartialValue)>,
    ) -> &mut Self {
        self.tags.extend(tags);
        self
    }

    /// Add a direct parent UID (removing it from indirect ancestors if present).
    pub fn add_parent(mut self, parent: EntityUID) -> Self {
        self.parents.insert(parent.clone());
        self.indirect_ancestors.remove(&parent);
        self
    }

    /// Remove a direct parent UID.
    pub fn remove_parent(mut self, parent: &EntityUID) -> Self {
        self.parents.remove(parent);
        self
    }

    /// Add a collection of direct parent UIDs.
    pub fn with_parents(
        &mut self,
        parents: impl IntoIterator<Item = EntityUID>,
    ) -> &mut Self {
        self.parents.extend(parents);
        self
    }

    /// Add an indirect ancestor UID (no‐op if it’s already a parent).
    pub fn add_indirect(mut self, anc: EntityUID) -> Self {
        if !self.parents.contains(&anc) {
            self.indirect_ancestors.insert(anc);
        }
        self
    }

    /// Remove an indirect ancestor UID.
    pub fn remove_indirect(mut self, anc: &EntityUID) -> Self {
        self.indirect_ancestors.remove(anc);
        self
    }

    /// Consume the builder and construct an `Entity`.
    ///
    /// Uses `Entity::new_with_attr_partial_value` to move in your maps/sets
    /// directly (no extra cloning).
    pub fn build(self) -> Entity {
        Entity::new_with_attr_partial_value(
            self.uid,
            self.attrs,
            self.indirect_ancestors,
            self.parents,
            self.tags,
        )
    }
}

/// Allow `EntityBuilder::from(entity)` when you own an `Entity`.
impl From<Entity> for EntityBuilder {
    fn from(entity: Entity) -> Self {
        EntityBuilder::from_entity(entity)
    }
}
