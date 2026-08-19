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
use std::collections::HashSet;
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