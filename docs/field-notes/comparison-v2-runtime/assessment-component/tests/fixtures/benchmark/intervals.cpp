bool overlaps(int first_start, int first_end, int second_start, int second_end) {
    return first_start <= second_end && second_start <= first_end;
}
