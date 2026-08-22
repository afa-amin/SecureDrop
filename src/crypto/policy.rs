//! Policy language and access-tree representation for CP-ABE.
//!
//! Supported syntax (case-insensitive keywords):
//!   clearance>=N
//!   department=foo
//!   role=bar
//!   AND / OR
//!   parentheses
//!
//! Examples:
//!   clearance>=4 AND department=intelligence
//!   (clearance>=3 OR role=admin) AND department=ops

use crate::error::{Result, SecureDropError};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Leaf attribute in the access tree.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Attribute {
    pub name: String,
    pub value: Option<String>, // None for pure presence attributes
}

impl Attribute {
    pub fn new(name: impl Into<String>, value: Option<String>) -> Self {
        Self {
            name: name.into().to_lowercase(),
            value: value.map(|v| v.to_lowercase()),
        }
    }

    pub fn clearance_ge(n: u32) -> Self {
        Self::new(format!("clearance>={}", n), None)
    }

    pub fn department(dept: &str) -> Self {
        Self::new("department", Some(dept.to_string()))
    }

    pub fn role(role: &str) -> Self {
        Self::new("role", Some(role.to_string()))
    }

    /// Canonical string form used as attribute identifier in the scheme.
    pub fn id(&self) -> String {
        match &self.value {
            Some(v) => format!("{}={}", self.name, v),
            None => self.name.clone(),
        }
    }

    /// Which authority governs this attribute, in multi-authority mode.
    /// `clearance>=4` -> "clearance"; `department=intelligence` -> "department".
    /// (Today this is just `self.name`, but it is kept as a distinct concept
    /// since a deployment may later want several attribute names under one
    /// authority, e.g. both `department=` and `division=` issued by the same
    /// HR authority.)
    pub fn authority(&self) -> String {
        // `clearance>=N` attributes store the whole comparison in `name`
        // (see `clearance_ge`), so strip the operator back off; all other
        // attributes store a bare name ("department", "role", ...) already.
        match self.name.split_once(">=") {
            Some((base, _)) => base.to_string(),
            None => self.name.clone(),
        }
    }
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id())
    }
}

/// Access structure node (threshold tree).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AccessNode {
    /// Leaf: single attribute
    Leaf(Attribute),
    /// Internal: threshold-k of children (k == children.len() → AND, k == 1 → OR)
    Threshold {
        threshold: usize,
        children: Vec<AccessNode>,
    },
}

impl AccessNode {
    pub fn and(children: Vec<AccessNode>) -> Self {
        let k = children.len();
        AccessNode::Threshold {
            threshold: k,
            children,
        }
    }

    pub fn or(children: Vec<AccessNode>) -> Self {
        AccessNode::Threshold {
            threshold: 1,
            children,
        }
    }

    pub fn leaf(attr: Attribute) -> Self {
        AccessNode::Leaf(attr)
    }

    /// Collect all leaf attributes that appear in the tree.
    pub fn collect_attributes(&self) -> HashSet<Attribute> {
        let mut set = HashSet::new();
        self.collect_into(&mut set);
        set
    }

    fn collect_into(&self, set: &mut HashSet<Attribute>) {
        match self {
            AccessNode::Leaf(a) => {
                set.insert(a.clone());
            }
            AccessNode::Threshold { children, .. } => {
                for c in children {
                    c.collect_into(set);
                }
            }
        }
    }

    /// Evaluate whether a set of attribute IDs satisfies the tree.
    pub fn satisfied_by(&self, attrs: &HashSet<String>) -> bool {
        match self {
            AccessNode::Leaf(a) => attrs.contains(&a.id()),
            AccessNode::Threshold {
                threshold,
                children,
            } => {
                let satisfied = children.iter().filter(|c| c.satisfied_by(attrs)).count();
                satisfied >= *threshold
            }
        }
    }
}

impl fmt::Display for AccessNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessNode::Leaf(a) => write!(f, "{}", a),
            AccessNode::Threshold {
                threshold,
                children,
            } => {
                if *threshold == children.len() {
                    write!(f, "(")?;
                    for (i, c) in children.iter().enumerate() {
                        if i > 0 {
                            write!(f, " AND ")?;
                        }
                        write!(f, "{}", c)?;
                    }
                    write!(f, ")")
                } else if *threshold == 1 {
                    write!(f, "(")?;
                    for (i, c) in children.iter().enumerate() {
                        if i > 0 {
                            write!(f, " OR ")?;
                        }
                        write!(f, "{}", c)?;
                    }
                    write!(f, ")")
                } else {
                    write!(f, "(threshold {} of ", threshold)?;
                    for (i, c) in children.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", c)?;
                    }
                    write!(f, ")")
                }
            }
        }
    }
}

/// Parse a human-readable policy string into an AccessNode.
pub fn parse_policy(input: &str) -> Result<AccessNode> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err(SecureDropError::InvalidPolicy("empty policy".into()));
    }
    let (node, rest) = parse_expr(&tokens)?;
    if !rest.is_empty() {
        return Err(SecureDropError::InvalidPolicy(format!(
            "unexpected trailing tokens: {:?}",
            rest
        )));
    }
    Ok(node)
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Attr(String),
    And,
    Or,
    LParen,
    RParen,
}

fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '(' {
            tokens.push(Token::LParen);
            chars.next();
            continue;
        }
        if c == ')' {
            tokens.push(Token::RParen);
            chars.next();
            continue;
        }
        let mut word = String::new();
        while let Some(&ch) = chars.peek() {
            if ch.is_whitespace() || ch == '(' || ch == ')' {
                break;
            }
            word.push(ch);
            chars.next();
        }
        let lower = word.to_lowercase();
        match lower.as_str() {
            "and" => tokens.push(Token::And),
            "or" => tokens.push(Token::Or),
            _ => tokens.push(Token::Attr(word)),
        }
    }
    Ok(tokens)
}

fn parse_expr(tokens: &[Token]) -> Result<(AccessNode, &[Token])> {
    let (left, mut rest) = parse_term(tokens)?;
    let mut nodes = vec![left];
    let mut is_and = None;

    while !rest.is_empty() {
        match rest[0] {
            Token::And => {
                if is_and == Some(false) {
                    return Err(SecureDropError::InvalidPolicy(
                        "mixed AND/OR without parentheses".into(),
                    ));
                }
                is_and = Some(true);
                rest = &rest[1..];
                let (n, r) = parse_term(rest)?;
                nodes.push(n);
                rest = r;
            }
            Token::Or => {
                if is_and == Some(true) {
                    return Err(SecureDropError::InvalidPolicy(
                        "mixed AND/OR without parentheses".into(),
                    ));
                }
                is_and = Some(false);
                rest = &rest[1..];
                let (n, r) = parse_term(rest)?;
                nodes.push(n);
                rest = r;
            }
            _ => break,
        }
    }

    let node = if nodes.len() == 1 {
        nodes.pop().unwrap()
    } else if is_and == Some(true) {
        AccessNode::and(nodes)
    } else {
        AccessNode::or(nodes)
    };
    Ok((node, rest))
}

fn parse_term(tokens: &[Token]) -> Result<(AccessNode, &[Token])> {
    if tokens.is_empty() {
        return Err(SecureDropError::InvalidPolicy(
            "unexpected end of policy".into(),
        ));
    }
    match &tokens[0] {
        Token::LParen => {
            let (node, rest) = parse_expr(&tokens[1..])?;
            if rest.is_empty() || rest[0] != Token::RParen {
                return Err(SecureDropError::InvalidPolicy(
                    "missing closing parenthesis".into(),
                ));
            }
            Ok((node, &rest[1..]))
        }
        Token::Attr(s) => {
            let attr = parse_attribute(s)?;
            Ok((AccessNode::leaf(attr), &tokens[1..]))
        }
        _ => Err(SecureDropError::InvalidPolicy(format!(
            "unexpected token: {:?}",
            tokens[0]
        ))),
    }
}

fn parse_attribute(s: &str) -> Result<Attribute> {
    let lower = s.to_lowercase();
    if let Some(rest) = lower.strip_prefix("clearance>=") {
        let n: u32 = rest.parse().map_err(|_| {
            SecureDropError::InvalidPolicy(format!("invalid clearance value: {}", rest))
        })?;
        if n < 1 || n > 10 {
            return Err(SecureDropError::InvalidPolicy(
                "clearance must be between 1 and 10".into(),
            ));
        }
        return Ok(Attribute::clearance_ge(n));
    }
    if let Some((name, value)) = lower.split_once('=') {
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() || value.is_empty() {
            return Err(SecureDropError::InvalidPolicy(format!(
                "malformed attribute: {}",
                s
            )));
        }
        match name {
            "department" | "role" => Ok(Attribute::new(name, Some(value.to_string()))),
            _ => Err(SecureDropError::UnknownAttribute(name.to_string())),
        }
    } else {
        Ok(Attribute::new(lower, None))
    }
}

/// Partition an access tree into one subtree per authority, for multi-authority
/// encryption. This is only possible if every OR / k-of-n threshold node's
/// leaves all belong to a single authority — under Chase's (TCC 2007)
/// multi-authority construction, distinct authorities can only be combined
/// with AND, never OR or general threshold, because each authority's
/// contribution is reconstructed independently and then summed centrally.
///
/// Returns a map from authority id -> the access-tree fragment (already an
/// AND of everything required from that authority).
pub fn partition_by_authority(
    node: &AccessNode,
) -> Result<HashMap<String, AccessNode>> {
    match node {
        AccessNode::Leaf(attr) => {
            let mut m = HashMap::new();
            m.insert(attr.authority(), AccessNode::Leaf(attr.clone()));
            Ok(m)
        }
        AccessNode::Threshold {
            threshold,
            children,
        } => {
            if *threshold == children.len() {
                // AND node: fine to span multiple authorities. Recurse and
                // merge; if two children touch the same authority, AND their
                // fragments together.
                let mut acc: HashMap<String, AccessNode> = HashMap::new();
                for child in children {
                    let child_map = partition_by_authority(child)?;
                    for (auth, frag) in child_map {
                        acc.entry(auth)
                            .and_modify(|existing| {
                                *existing =
                                    AccessNode::and(vec![existing.clone(), frag.clone()]);
                            })
                            .or_insert(frag);
                    }
                }
                Ok(acc)
            } else {
                // OR or general k-of-n: every leaf underneath must belong to
                // the same authority, since we cannot let two authorities
                // stand in for one another (that would let an authority
                // decrypt on behalf of another, or need cross-authority
                // interaction to prevent collusion).
                let leaves = node.collect_attributes();
                let authorities: HashSet<String> =
                    leaves.iter().map(|a| a.authority()).collect();
                if authorities.len() > 1 {
                    return Err(SecureDropError::MixedAuthorityPolicy(node.to_string()));
                }
                let auth = authorities
                    .into_iter()
                    .next()
                    .ok_or_else(|| SecureDropError::InvalidPolicy("empty node".into()))?;
                let mut m = HashMap::new();
                m.insert(auth, node.clone());
                Ok(m)
            }
        }
    }
}

/// Expand a user's numeric clearance into the set of attributes they receive.
/// clearance=4 → clearance>=1, clearance>=2, clearance>=3, clearance>=4
pub fn expand_clearance(level: u32) -> Vec<Attribute> {
    (1..=level).map(Attribute::clearance_ge).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_and() {
        let tree = parse_policy("clearance>=4 AND department=intelligence").unwrap();
        let attrs: HashSet<_> = ["clearance>=4".into(), "department=intelligence".into()]
            .into_iter()
            .collect();
        assert!(tree.satisfied_by(&attrs));
        let bad: HashSet<_> = ["clearance>=3".into(), "department=intelligence".into()]
            .into_iter()
            .collect();
        assert!(!tree.satisfied_by(&bad));
    }

    #[test]
    fn parse_or_with_parens() {
        let tree = parse_policy("(clearance>=3 OR role=admin) AND department=ops").unwrap();
        let good: HashSet<_> = ["clearance>=3".into(), "department=ops".into()]
            .into_iter()
            .collect();
        assert!(tree.satisfied_by(&good));
    }
}