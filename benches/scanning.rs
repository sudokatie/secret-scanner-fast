use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use secret_scanner_fast::detection::entropy::calculate_entropy;
use secret_scanner_fast::detection::matcher::Matcher;
use secret_scanner_fast::detection::rules::Severity;
use std::path::Path;

fn bench_entropy_calculation(c: &mut Criterion) {
    let test_strings = vec![
        ("short", "abc123"),
        ("medium", "AKIAIOSFODNN7EXAMPLE"),
        ("long", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
    ];

    let mut group = c.benchmark_group("entropy");
    for (name, input) in test_strings {
        group.bench_with_input(BenchmarkId::new("calculate", name), &input, |b, s| {
            b.iter(|| calculate_entropy(black_box(s)))
        });
    }
    group.finish();
}

fn bench_pattern_matching(c: &mut Criterion) {
    let matcher = Matcher::new(Severity::Low);
    let file = Path::new("test.py");

    let test_lines = vec![
        ("clean", "x = 42"),
        ("aws_key", "aws_key = AKIAIOSFODNN7EXAMPLE"),
        ("github_token", "token = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ("multiple", "key1 = AKIAIOSFODNN7EXAMPLE; token = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
    ];

    let mut group = c.benchmark_group("pattern_matching");
    for (name, line) in test_lines {
        group.bench_with_input(BenchmarkId::new("match_line", name), &line, |b, l| {
            b.iter(|| matcher.match_line(black_box(l), 1, file))
        });
    }
    group.finish();
}

fn bench_content_scanning(c: &mut Criterion) {
    let matcher = Matcher::new(Severity::Low);
    let file = Path::new("test.py");

    // Generate test content of various sizes
    let small_content = "x = 42\ny = 'hello'\nz = AKIAIOSFODNN7EXAMPLE\n";
    let medium_content = small_content.repeat(100);
    let large_content = small_content.repeat(1000);

    let mut group = c.benchmark_group("content_scanning");
    
    group.bench_with_input(BenchmarkId::new("match_content", "small"), &small_content, |b, c| {
        b.iter(|| matcher.match_content(black_box(c), file))
    });
    
    group.bench_with_input(BenchmarkId::new("match_content", "medium"), &medium_content, |b, c| {
        b.iter(|| matcher.match_content(black_box(c), file))
    });
    
    group.bench_with_input(BenchmarkId::new("match_content", "large"), &large_content, |b, c| {
        b.iter(|| matcher.match_content(black_box(c), file))
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_entropy_calculation,
    bench_pattern_matching,
    bench_content_scanning,
);
criterion_main!(benches);
